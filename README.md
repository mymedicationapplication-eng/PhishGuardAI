# PhishGuard - Enterprise Phishing Detection Platform

AI-powered phishing detection system with 96.8% accuracy. Built with Flask, TF-IDF, and Logistic Regression.

## Features

- **Real-Time Detection** - Instant phishing analysis with confidence scoring
- **Batch Processing** - Analyze multiple messages via CSV/TXT upload
- **Advanced Analytics** - Comprehensive dashboards and performance metrics
- **Admin Panel** - Complete user management with data export (Excel/PDF)
- **Audit Trail** - Full activity logging for compliance

## Quick Start

### Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run Application

```bash
python run.py
```

Access at: `http://127.0.0.1:5000`

## Default Accounts

**Administrator:**
- Email: `admin@gmail.com`
- Password: `Admin@1234`

**User:**
- Email: `Fatimahali@gmail.com`
- Password: `Fatimahali@1234`

⚠️ **Change passwords immediately after first login**

## Tech Stack

- Flask 3.0.3
- scikit-learn 1.6.1
- SQLite / PostgreSQL
- Bootstrap 5
- Chart.js
- openpyxl (Excel export)
- reportlab (PDF export)

## Model Performance

- **Accuracy:** 96.8%
- **Precision:** 93.9%
- **Recall:** 98.1%
- **F1 Score:** 96.0%
- **ROC-AUC:** 99.5%
- **Training Data:** 18,631 records

## Admin Capabilities

- User management (search, filter, export)
- Scan monitoring (search, filter, export)
- Contact message management
- Audit log (search, filter, export)
- Model performance oversight
- Excel/PDF data export

## Production Deployment

1. Set strong `SECRET_KEY` environment variable
2. Use PostgreSQL instead of SQLite
3. Configure Gunicorn/Nginx
4. Enable HTTPS
5. Set up regular backups

## License

Proprietary - All rights reserved

## Support

For issues or questions, contact the development team.
