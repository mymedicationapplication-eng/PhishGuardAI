# PhishGuard Web Application

A professional light-themed phishing detection web app built around your saved **TF-IDF + Logistic Regression** model and the uploaded **PhishGuard** branding assets.

## Included
- Modern landing page
- Authentication screens: login, register, reset password
- User dashboard
- Single message scan
- Batch analysis for CSV/TXT
- Scan history
- Analytics
- Profile management
- Admin center:
  - overview
  - user management
  - scan records
  - audit log
  - model center

## Tech Stack
- Flask
- SQLite
- Jinja2 templates
- Bootstrap 5 + custom CSS
- Chart.js
- scikit-learn / joblib

## Project Structure
```text
phishguard_webapp/
├── app/
│   ├── __init__.py
│   ├── auth.py
│   ├── config.py
│   ├── db.py
│   ├── routes.py
│   ├── model_service.py
│   ├── rule_engine.py
│   ├── text_utils.py
│   ├── static/
│   └── templates/
├── artifacts/
│   ├── phishing_detector.joblib
│   └── metrics.json
├── requirements.txt
└── run.py
```

## Quick Start

### 1) Create virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Run the app
```bash
python run.py
```

Open:
```text
http://127.0.0.1:5000
```

## Default Admin Account
The app seeds a default administrator on first run:

- **Email:** `admin@phishguard.local`
- **Password:** `Admin@12345`

Change it immediately after login.

## Notes
- The AI model is loaded from `artifacts/phishing_detector.joblib`.
- Model metrics are loaded from `artifacts/metrics.json`.
- `scikit-learn==1.6.1` is pinned to match the saved artifact version.
- The app uses PBKDF2 password hashing and role-based access checks.
- For batch analysis:
  - CSV: either a `message` column or the first column is used.
  - TXT: one message per line.

## Deployment Notes
For production:
- Set a strong `SECRET_KEY`
- Replace SQLite with PostgreSQL if needed
- Serve behind Gunicorn / Nginx
- Add CSRF protection and stricter file validation
- Configure HTTPS
