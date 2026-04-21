import secrets
from datetime import datetime, timedelta, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager


class User(UserMixin, db.Model):
    id                     = db.Column(db.Integer, primary_key=True)
    username               = db.Column(db.String(80), nullable=False)
    email                  = db.Column(db.String(120), unique=True, nullable=False)
    password_hash          = db.Column(db.String(255), nullable=False)
    totp_secret            = db.Column(db.String(32), nullable=False)
    twofa_enabled          = db.Column(db.Boolean, default=False)
    device_credential_hash = db.Column(db.String(255), nullable=True)
    reset_token            = db.Column(db.String(128), nullable=True)
    reset_token_expiry     = db.Column(db.DateTime, nullable=True)
    created_at             = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # ── password ──────────────────────────────────────────────────────────────
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ── device credential (QR login) ──────────────────────────────────────────
    def set_device_credential(self, raw_token):
        self.device_credential_hash = generate_password_hash(raw_token)

    def check_device_credential(self, raw_token):
        if not self.device_credential_hash:
            return False
        return check_password_hash(self.device_credential_hash, raw_token)

    # ── password reset ────────────────────────────────────────────────────────
    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(48)
        self.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        return self.reset_token

    def reset_token_valid(self):
        if not self.reset_token or not self.reset_token_expiry:
            return False
        expiry = self.reset_token_expiry
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < expiry

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expiry = None


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
