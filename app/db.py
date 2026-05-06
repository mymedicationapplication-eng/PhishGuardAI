import json
import sqlite3
from pathlib import Path
from flask import current_app, g
from .text_utils import pbkdf2_hash
from .model_service import get_metrics

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    institution TEXT,
    bio TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_message TEXT NOT NULL,
    normalized_text TEXT NOT NULL,
    prediction_label TEXT NOT NULL,
    confidence REAL NOT NULL,
    phishing_probability REAL NOT NULL,
    legitimate_probability REAL NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    suspicious_keywords TEXT,
    detected_urls TEXT,
    recommendation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    action_type TEXT NOT NULL,
    target_type TEXT,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(actor_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS training_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    accuracy REAL,
    precision REAL,
    recall REAL,
    f1_score REAL,
    roc_auc REAL,
    train_size INTEGER,
    test_size INTEGER,
    total_records INTEGER,
    model_type TEXT,
    trained_at TEXT,
    confusion_matrix TEXT
);
"""

def get_db():
    if "db" not in g:
        db_path = Path(current_app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()
    from flask import current_app
    current_app.teardown_appcontext(close_db)

def query_one(query, params=()):
    return get_db().execute(query, params).fetchone()

def query_all(query, params=()):
    return get_db().execute(query, params).fetchall()

def execute(query, params=()):
    db = get_db()
    cur = db.execute(query, params)
    db.commit()
    return cur

def seed_default_admin():
    from .text_utils import utc_now_iso
    
    # Create default admin user
    existing_admin = query_one("SELECT id FROM users WHERE email = ?", ("admin@gmail.com",))
    if not existing_admin:
        salt, hashed = pbkdf2_hash("Admin@1234")
        execute(
            """
            INSERT INTO users (full_name, email, password_hash, password_salt, role, institution, bio, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "PhishGuard Administrator",
                "admin@gmail.com",
                hashed,
                salt,
                "admin",
                "PhishGuard Security",
                "System administrator account.",
                1,
                utc_now_iso(),
            ),
        )
        log_action(None, "seed_admin", "user", "info", "Default admin account created.")
    
    # Create default regular user
    existing_user = query_one("SELECT id FROM users WHERE email = ?", ("Fatimahali@gmail.com",))
    if not existing_user:
        salt, hashed = pbkdf2_hash("Fatimahali@1234")
        execute(
            """
            INSERT INTO users (full_name, email, password_hash, password_salt, role, institution, bio, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Fatimah Ali",
                "Fatimahali@gmail.com",
                hashed,
                salt,
                "user",
                "PhishGuard",
                "Default user account.",
                1,
                utc_now_iso(),
            ),
        )
        log_action(None, "seed_user", "user", "info", "Default user account created.")

def seed_training_run():
    metrics = get_metrics()
    if not metrics:
        return
    existing = query_one("SELECT id FROM training_runs LIMIT 1")
    if existing:
        return
    execute(
        """
        INSERT INTO training_runs (
            accuracy, precision, recall, f1_score, roc_auc,
            train_size, test_size, total_records, model_type,
            trained_at, confusion_matrix
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            metrics.get("accuracy"),
            metrics.get("precision"),
            metrics.get("recall"),
            metrics.get("f1_score"),
            metrics.get("roc_auc"),
            metrics.get("train_size"),
            metrics.get("test_size"),
            metrics.get("total_records"),
            metrics.get("model_type"),
            metrics.get("trained_at"),
            json.dumps(metrics.get("confusion_matrix", [])),
        ),
    )

def log_action(actor_user_id, action_type, target_type, severity, description):
    from .text_utils import utc_now_iso
    execute(
        """
        INSERT INTO audit_logs (actor_user_id, action_type, target_type, severity, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor_user_id, action_type, target_type, severity, description, utc_now_iso()),
    )
