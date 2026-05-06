import csv
import io
import os
import re
import json
import hashlib
import secrets
from datetime import datetime, timezone
from typing import List

SPACE_RE = re.compile(r"\s+")
NON_SAFE_RE = re.compile(r"[^\w\s:/?&.=+@#%-]")
URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = text.strip().lower()
    text = NON_SAFE_RE.sub(" ", text)
    text = SPACE_RE.sub(" ", text).strip()
    return text

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return list(dict.fromkeys(m.group(0).rstrip(".,);]") for m in URL_RE.finditer(text)))

def pbkdf2_hash(password: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000,
    ).hex()
    return salt, hashed

def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, computed = pbkdf2_hash(password, salt=salt)
    return secrets.compare_digest(computed, expected_hash)

def load_messages_from_upload(file_storage):
    filename = file_storage.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower()
    content = file_storage.read()
    file_storage.seek(0)
    if ext == "txt":
        text = content.decode("utf-8", errors="ignore")
        return [line.strip() for line in text.splitlines() if line.strip()]
    if ext == "csv":
        text_stream = io.StringIO(content.decode("utf-8", errors="ignore"))
        reader = csv.DictReader(text_stream)
        messages = []
        if reader.fieldnames:
            fields = [f.strip().lower() for f in reader.fieldnames]
            message_field = None
            for name in ["message", "text", "email", "content", "body"]:
                if name in fields:
                    message_field = reader.fieldnames[fields.index(name)]
                    break
            if message_field:
                text_stream.seek(0)
                reader = csv.DictReader(text_stream)
                for row in reader:
                    value = (row.get(message_field) or "").strip()
                    if value:
                        messages.append(value)
                return messages
        text_stream.seek(0)
        plain_reader = csv.reader(text_stream)
        for row in plain_reader:
            if not row:
                continue
            value = (row[0] or "").strip()
            if value and value.lower() not in {"message", "text", "email", "content", "body"}:
                messages.append(value)
        return messages
    return []
