from app import create_app, db
from app.models import User
import pyotp, sys

app = create_app()
results = []

with app.app_context():
    # clean slate
    User.query.filter_by(email="test@example.com").delete()
    db.session.commit()

    # 1. create user
    u = User(username="testuser", email="test@example.com", totp_secret=pyotp.random_base32())
    u.set_password("TestPass123!")
    db.session.add(u)
    db.session.commit()
    results.append(("User created", u.id is not None))

    # 2. password hashing
    results.append(("Correct password accepted", u.check_password("TestPass123!")))
    results.append(("Wrong password rejected",  not u.check_password("wrongpass")))

    # 3. TOTP
    totp = pyotp.TOTP(u.totp_secret)
    results.append(("TOTP token valid", totp.verify(totp.now())))

    # 4. query
    found = User.query.filter_by(email="test@example.com").first()
    results.append(("User queryable from DB", found is not None))

    # 5. all columns present
    import sqlalchemy as sa
    cols = [c["name"] for c in sa.inspect(db.engine).get_columns("user")]
    expected = ["id","username","email","password_hash","totp_secret",
                "twofa_enabled","device_credential_hash","reset_token",
                "reset_token_expiry","created_at"]
    results.append(("All columns present", all(c in cols for c in expected)))

    # 6. HTTP routes
    with app.test_client() as c:
        for route, expected_code in [("/", 200), ("/auth/login", 200),
                                      ("/auth/register", 200), ("/home", 302),
                                      ("/dashboard", 302)]:
            r = c.get(route, follow_redirects=False)
            results.append((f"GET {route} -> {expected_code}", r.status_code == expected_code))

    # cleanup
    db.session.delete(found)
    db.session.commit()
    results.append(("Cleanup", True))

print()
for name, ok in results:
    print(f"  {'[PASS]' if ok else '[FAIL]'} {name}")

all_ok = all(ok for _, ok in results)
print()
print("=" * 40)
print("RESULT:", "ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED")
print("=" * 40)
sys.exit(0 if all_ok else 1)
