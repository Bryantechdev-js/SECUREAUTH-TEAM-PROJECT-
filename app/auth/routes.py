import io
import json
import base64
import secrets
import hashlib
import pyotp
import qrcode
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from flask import (render_template, request, redirect, url_for,
                   flash, session, send_file, current_app)
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.auth import auth_bp


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fernet() -> Fernet:
    """Derive a stable Fernet key from the app SECRET_KEY."""
    raw = current_app.config["SECRET_KEY"].encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def generate_qr_base64(data: str) -> str:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()


def make_credential_token(user: User) -> str:
    """Generate a unique, unguessable raw token for this user."""
    return secrets.token_urlsafe(48)


def build_credential_file(user: User, raw_token: str) -> bytes:
    """
    Encrypt a JSON credential payload with Fernet.
    Payload: { email, username, token, issued_at }
    """
    payload = json.dumps({
        "email":     user.email,
        "username":  user.username,
        "token":     raw_token,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }).encode()
    return _fernet().encrypt(payload)


def decode_credential_file(data: bytes) -> dict | None:
    """Decrypt and parse a credential file. Returns None on any failure."""
    try:
        return json.loads(_fernet().decrypt(data).decode())
    except Exception:
        return None


# ── Auth Routes ───────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("auth.register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "warning")
            return redirect(url_for("auth.register"))

        user = User(username=username, email=email,
                    totp_secret=pyotp.random_base32())
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session["pending_setup_user_id"] = user.id
        flash("Account created! Now set up your 2FA.", "success")
        return redirect(url_for("auth.setup_2fa"))

    return render_template("auth/register.html")


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    user_id = session.get("pending_setup_user_id")
    if not user_id:
        flash("No account pending 2FA setup.", "warning")
        return redirect(url_for("auth.register"))

    user = db.session.get(User, user_id)
    if not user:
        flash("Account not found.", "danger")
        return redirect(url_for("auth.register"))

    # ── TOTP QR ──────────────────────────────────────────────
    totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email, issuer_name="SecureAuth"
    )
    totp_qr = generate_qr_base64(totp_uri)

    # ── Device credential QR ─────────────────────────────────
    # Generate (or reuse) the raw token for this session
    if "device_raw_token" not in session:
        raw_token = make_credential_token(user)
        user.set_device_credential(raw_token)
        db.session.commit()
        session["device_raw_token"] = raw_token
    else:
        raw_token = session["device_raw_token"]

    # The QR encodes the download URL so a phone camera tap triggers download
    download_url = url_for("auth.download_credential", _external=True)
    # Encode token in the QR so the download endpoint can verify it
    cred_qr_data = f"{download_url}?t={raw_token}"
    cred_qr      = generate_qr_base64(cred_qr_data)

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        if pyotp.TOTP(user.totp_secret).verify(token):
            user.twofa_enabled = True
            db.session.commit()
            session.pop("pending_setup_user_id", None)
            session.pop("device_raw_token", None)
            flash("2FA enabled successfully. You can now log in.", "success")
            return redirect(url_for("auth.login"))
        flash("Invalid code — please try again.", "danger")

    return render_template("auth/setup_2fa.html",
                           totp_qr=totp_qr,
                           totp_secret=user.totp_secret,
                           cred_qr=cred_qr,
                           raw_token=raw_token,
                           email=user.email)


@auth_bp.route("/download-credential")
def download_credential():
    """
    Called when user scans the credential QR code with their phone.
    Validates the token, builds the encrypted file, sends it for download.
    """
    raw_token = request.args.get("t", "").strip()
    if not raw_token:
        flash("Invalid credential link.", "danger")
        return redirect(url_for("auth.login"))

    # Find the user whose device_credential_hash matches this token
    user = None
    for u in User.query.all():
        if u.check_device_credential(raw_token):
            user = u
            break

    if not user:
        flash("Credential not found or already used.", "danger")
        return redirect(url_for("auth.login"))

    encrypted = build_credential_file(user, raw_token)
    buf = io.BytesIO(encrypted)
    buf.seek(0)
    filename = f"secureauth_{user.username}.secureauth"
    return send_file(buf, as_attachment=True,
                     download_name=filename,
                     mimetype="application/octet-stream")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    if request.method == "POST":
        login_type = request.form.get("login_type", "password")

        # ── Option A: File-based (device credential) login ───
        if login_type == "credential":
            cred_file = request.files.get("credential_file")
            if not cred_file or cred_file.filename == "":
                flash("Please select your .secureauth credential file.", "warning")
                return redirect(url_for("auth.login"))

            payload = decode_credential_file(cred_file.read())
            if not payload:
                flash("Invalid or corrupted credential file.", "danger")
                return redirect(url_for("auth.login"))

            user = User.query.filter_by(email=payload.get("email")).first()
            if not user or not user.check_device_credential(payload.get("token", "")):
                flash("Credential does not match any account.", "danger")
                return redirect(url_for("auth.login"))

            login_user(user)
            flash(f"Welcome back, {user.username}! Signed in with device credential.", "success")
            return redirect(url_for("main.home"))

        # ── Option B: Password login ──────────────────────────
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "").strip()
        user     = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if user.twofa_enabled:
                session["pre_2fa_user_id"] = user.id
                return redirect(url_for("auth.verify_2fa"))
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("main.home"))

        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user:
        flash("Account not found.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        if pyotp.TOTP(user.totp_secret).verify(token):
            login_user(user)
            session.pop("pre_2fa_user_id", None)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("main.home"))
        flash("Invalid authentication code.", "danger")

    return render_template("auth/verify_2fa.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("pre_2fa_user_id", None)
    session.pop("pending_setup_user_id", None)
    session.pop("device_raw_token", None)
    flash("You've been logged out securely.", "info")
    return redirect(url_for("auth.login"))
