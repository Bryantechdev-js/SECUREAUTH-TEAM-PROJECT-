from app import create_app, db
from app.models import User
import pyotp, sys

app = create_app()
results = []

with app.app_context():
    User.query.filter_by(email="setup@test.com").delete()
    db.session.commit()

    u = User(username="setuptest", email="setup@test.com",
             totp_secret=pyotp.random_base32())
    u.set_password("Test1234!")
    db.session.add(u)
    db.session.commit()

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["pending_setup_user_id"] = u.id

        r    = c.get("/auth/setup-2fa")
        body = r.data.decode()

        results = [
            ("Status 200",           r.status_code == 200),
            ("QR code rendered",     "data:image/png;base64," in body),
            ("TOTP secret in page",  u.totp_secret in body),
            ("jsOTP CDN included",   "jsotp" in body),
            ("Live code element",    "liveCode" in body),
            ("Countdown ring SVG",   "countRing" in body),
            ("Auto-fill function",   "autoFill" in body),
            ("Copy function",        "copyCode" in body),
            ("6 OTP input boxes",    body.count("otp-box") >= 6),
            ("Step indicator",       "step done" in body),
        ]

    db.session.delete(u)
    db.session.commit()

print()
for name, ok in results:
    print(f"  {'[PASS]' if ok else '[FAIL]'} {name}")

all_ok = all(ok for _, ok in results)
print()
print("=" * 42)
print("RESULT:", "ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED")
print("=" * 42)
sys.exit(0 if all_ok else 1)
