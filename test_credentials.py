import io, sys
import pyotp
from app import create_app, db
from app.models import User
from app.auth.routes import (build_credential_file, decode_credential_file,
                              make_credential_token)

app = create_app()
results = []

def check(name, ok):
    results.append((name, ok))
    print(f"  {'[PASS]' if ok else '[FAIL]'} {name}")

print("\n--- SecureAuth Full Test Suite ---\n")

with app.app_context():
    # clean up
    User.query.filter_by(email="cred@test.com").delete()
    db.session.commit()

    # 1. create user
    u = User(username="credtest", email="cred@test.com",
             totp_secret=pyotp.random_base32())
    u.set_password("TestPass123!")
    db.session.add(u)
    db.session.commit()
    check("User created", u.id is not None)

    # 2. password hashing
    check("Correct password accepted", u.check_password("TestPass123!"))
    check("Wrong password rejected",   not u.check_password("wrong"))

    # 3. TOTP
    totp = pyotp.TOTP(u.totp_secret)
    check("TOTP token valid", totp.verify(totp.now()))

    # 4. credential token generation
    raw_token = make_credential_token(u)
    check("Raw token generated", len(raw_token) > 20)

    # 5. store and verify device credential
    u.set_device_credential(raw_token)
    db.session.commit()
    check("Device credential stored",  u.device_credential_hash is not None)
    check("Device credential matches", u.check_device_credential(raw_token))
    check("Wrong token rejected",      not u.check_device_credential("wrongtoken"))

    # 6. build and decrypt credential file
    encrypted = build_credential_file(u, raw_token)
    check("Credential file built",     len(encrypted) > 50)
    payload = decode_credential_file(encrypted)
    check("Credential file decrypted", payload is not None)
    check("Email in payload",          payload.get("email") == "cred@test.com")
    check("Token in payload",          payload.get("token") == raw_token)
    check("Username in payload",       payload.get("username") == "credtest")

    # 7. corrupted file rejected
    check("Corrupted file rejected",   decode_credential_file(b"notvalid") is None)

    # 8. HTTP routes
    with app.test_client() as c:
        routes = [
            ("/",              200),
            ("/auth/login",    200),
            ("/auth/register", 200),
            ("/home",          302),
            ("/dashboard",     302),
        ]
        for route, expected in routes:
            r = c.get(route, follow_redirects=False)
            check(f"GET {route} -> {expected}", r.status_code == expected)

        # 9. credential file download endpoint
        with c.session_transaction() as sess:
            sess["pending_setup_user_id"] = u.id
        r = c.get(f"/auth/download-credential?t={raw_token}")
        check("Download credential endpoint 200", r.status_code == 200)
        check("Response is binary file",
              b"application/octet-stream" in r.content_type.encode()
              or r.content_type == "application/octet-stream")

        # 10. file-based login
        encrypted_file = build_credential_file(u, raw_token)
        r = c.post("/auth/login",
                   data={"login_type": "credential",
                         "credential_file": (io.BytesIO(encrypted_file),
                                             "test.secureauth")},
                   content_type="multipart/form-data",
                   follow_redirects=False)
        check("Credential login redirects", r.status_code == 302)

    # cleanup
    db.session.delete(u)
    db.session.commit()
    check("Cleanup", True)

print()
all_ok = all(ok for _, ok in results)
passed = sum(ok for _, ok in results)
print(f"{'='*42}")
print(f"  {passed}/{len(results)} tests passed")
print(f"  RESULT: {'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}")
print(f"{'='*42}\n")
sys.exit(0 if all_ok else 1)
