import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishguard-dev-secret-key")
    DATABASE = str(BASE_DIR / "instance" / "phishguard.db")
    MODEL_PATH = str(BASE_DIR / "artifacts" / "phishing_detector.joblib")
    METRICS_PATH = str(BASE_DIR / "artifacts" / "metrics.json")
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB
    ALLOWED_UPLOAD_EXTENSIONS = {"csv", "txt"}
