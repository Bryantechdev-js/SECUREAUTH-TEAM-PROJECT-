# SecureAuth Team Project

A collaborative student project implementing secure login, registration, and Two-Factor Authentication (2FA) using Flask, SQLite, and a Git/GitHub team workflow.

## Features
- User registration with password hashing
- Secure login with session management
- TOTP-based 2FA (Google Authenticator / Authy)
- QR code setup for authenticator apps
- Protected dashboard (login required)
- Secure logout

## Tech Stack
- Python / Flask
- SQLite + Flask-SQLAlchemy
- Flask-Login
- PyOTP + QRCode
- Bootstrap 5

## Installation

```bash
git clone https://github.com/yourusername/secureauth-team-project.git
cd secureauth-team-project/app
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

Visit `http://127.0.0.1:5000`

## Project Structure

```
app/
├── __init__.py        # App factory
├── models.py          # User model
├── config.py          # Configuration
├── run.py             # Entry point
├── auth/
│   ├── __init__.py    # Auth blueprint
│   └── routes.py      # Register, login, 2FA, logout
├── main/
│   ├── __init__.py    # Main blueprint
│   └── routes.py      # Home, dashboard
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   └── auth/
│       ├── register.html
│       ├── login.html
│       ├── setup_2fa.html
│       └── verify_2fa.html
└── static/css/style.css
```

## Team Workflow

| Branch | Purpose |
|--------|---------|
| `main` | Stable production code |
| `develop` | Integration branch |
| `feature/*` | New features |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation |

## Security Notes
- Passwords are hashed with Werkzeug's `generate_password_hash`
- TOTP secrets are generated per-user with PyOTP
- Sessions are cleared on logout
- `SECRET_KEY` must be changed before production deployment

## Authors
- Member 1: Backend / Auth
- Member 2: 2FA / Security
- Member 3: UI / Docs / Testing
