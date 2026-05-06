import io
import csv
import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, g
from .auth import login_required, admin_required
from .db import query_one, query_all, execute, log_action
from .text_utils import normalize_text, load_messages_from_upload, pbkdf2_hash, utc_now_iso
from .model_service import predict_message, get_metrics
from .rule_engine import analyze_rules

main_bp = Blueprint("main", __name__)

def build_scan_result(message):
    normalized = normalize_text(message)
    ai = predict_message(normalized or message)
    rules = analyze_rules(message, ai["phishing_probability"])
    return {
        "normalized_text": normalized,
        "prediction_label": ai["label"],
        "confidence": ai["confidence"],
        "phishing_probability": ai["phishing_probability"],
        "legitimate_probability": ai["legitimate_probability"],
        "risk_score": rules["risk_score"],
        "risk_level": rules["risk_level"],
        "suspicious_keywords": rules["suspicious_keywords"],
        "detected_urls": rules["detected_urls"],
        "recommendation": rules["recommendation"],
    }

def get_user_dashboard_stats(user_id):
    totals = query_one(
        """
        SELECT
            COUNT(*) AS total_scans,
            SUM(CASE WHEN prediction_label = 'Phishing' THEN 1 ELSE 0 END) AS phishing_count,
            SUM(CASE WHEN prediction_label = 'Legitimate' THEN 1 ELSE 0 END) AS legitimate_count,
            SUM(CASE WHEN risk_level = 'High' THEN 1 ELSE 0 END) AS high_risk_count
        FROM scans WHERE user_id = ?
        """,
        (user_id,),
    )
    return totals

def get_admin_stats():
    return query_one(
        """
        SELECT
            (SELECT COUNT(*) FROM users) AS total_users,
            (SELECT COUNT(*) FROM scans) AS total_scans,
            (SELECT COUNT(*) FROM scans WHERE prediction_label = 'Phishing') AS phishing_count,
            (SELECT COUNT(*) FROM scans WHERE prediction_label = 'Legitimate') AS legitimate_count,
            (SELECT COUNT(*) FROM audit_logs) AS audit_count,
            (SELECT COUNT(*) FROM contact_messages) AS contact_count
        """
    )

@main_bp.route("/")
def landing():
    metrics = get_metrics()
    return render_template("landing.html", metrics=metrics)

@main_bp.route("/contact", methods=["POST"])
def contact():
    full_name = (request.form.get("full_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    subject = (request.form.get("subject") or "").strip()
    message = (request.form.get("message") or "").strip()
    if not full_name or not email or not message:
        flash("Please provide your name, email, and message before submitting.", "warning")
        return redirect(url_for("main.landing") + "#contact")
    execute(
        """
        INSERT INTO contact_messages (full_name, email, subject, message, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (full_name, email, subject, message, utc_now_iso()),
    )
    log_action(None, "submit_contact", "contact_message", "info", f"New contact message from {email}.")
    flash("Thank you — your message has been received. Our team will review it shortly.", "success")
    return redirect(url_for("main.landing") + "#contact")

@main_bp.route("/dashboard")
@login_required
def dashboard():
    stats = get_user_dashboard_stats(session["user_id"])
    recent_scans = query_all(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
        (session["user_id"],),
    )
    return render_template("app/dashboard.html", stats=stats, recent_scans=recent_scans)

@main_bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    result = None
    message = ""
    if request.method == "POST":
        message = (request.form.get("message") or "").strip()
        if not message:
            flash("Please enter a message to analyze.", "warning")
            return render_template("app/scan.html", result=None, message=message)
        result = build_scan_result(message)
        execute(
            """
            INSERT INTO scans (
                user_id, original_message, normalized_text, prediction_label, confidence,
                phishing_probability, legitimate_probability, risk_score, risk_level,
                suspicious_keywords, detected_urls, recommendation, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                message,
                result["normalized_text"],
                result["prediction_label"],
                result["confidence"],
                result["phishing_probability"],
                result["legitimate_probability"],
                result["risk_score"],
                result["risk_level"],
                json.dumps(result["suspicious_keywords"]),
                json.dumps(result["detected_urls"]),
                result["recommendation"],
                utc_now_iso(),
            ),
        )
        log_action(session["user_id"], "scan_message", "scan", "info", f"Message scanned with result {result['prediction_label']}.")
    return render_template("app/scan.html", result=result, message=message)

@main_bp.route("/batch", methods=["GET", "POST"])
@login_required
def batch():
    results = None
    if request.method == "POST":
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Please upload a CSV or TXT file.", "warning")
            return render_template("app/batch.html", results=None)
        ext = upload.filename.rsplit(".", 1)[-1].lower()
        if ext not in {"csv", "txt"}:
            flash("Only CSV and TXT files are supported.", "danger")
            return render_template("app/batch.html", results=None)
        messages = load_messages_from_upload(upload)
        if not messages:
            flash("No analyzable messages were found in the uploaded file.", "warning")
            return render_template("app/batch.html", results=None)
        results = []
        for message in messages[:200]:
            result = build_scan_result(message)
            results.append({"message": message, **result})
            execute(
                """
                INSERT INTO scans (
                    user_id, original_message, normalized_text, prediction_label, confidence,
                    phishing_probability, legitimate_probability, risk_score, risk_level,
                    suspicious_keywords, detected_urls, recommendation, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["user_id"],
                    message,
                    result["normalized_text"],
                    result["prediction_label"],
                    result["confidence"],
                    result["phishing_probability"],
                    result["legitimate_probability"],
                    result["risk_score"],
                    result["risk_level"],
                    json.dumps(result["suspicious_keywords"]),
                    json.dumps(result["detected_urls"]),
                    result["recommendation"],
                    utc_now_iso(),
                ),
            )
        log_action(session["user_id"], "batch_scan", "scan", "info", f"Batch file processed with {len(results)} messages.")
    return render_template("app/batch.html", results=results)

@main_bp.route("/batch/download", methods=["POST"])
@login_required
def batch_download():
    payload = request.form.get("payload") or "[]"
    try:
        rows = json.loads(payload)
    except Exception:
        rows = []
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["message", "prediction_label", "confidence", "phishing_probability", "legitimate_probability", "risk_score", "risk_level", "recommendation"])
    for row in rows:
        writer.writerow([
            row.get("message", ""),
            row.get("prediction_label", ""),
            row.get("confidence", ""),
            row.get("phishing_probability", ""),
            row.get("legitimate_probability", ""),
            row.get("risk_score", ""),
            row.get("risk_level", ""),
            row.get("recommendation", ""),
        ])
    memory = io.BytesIO(output.getvalue().encode("utf-8"))
    memory.seek(0)
    return send_file(memory, mimetype="text/csv", as_attachment=True, download_name="phishguard_batch_results.csv")

@main_bp.route("/history")
@login_required
def history():
    search = (request.args.get("q") or "").strip().lower()
    risk = (request.args.get("risk") or "").strip()
    label = (request.args.get("label") or "").strip()
    query = "SELECT * FROM scans WHERE user_id = ?"
    params = [session["user_id"]]
    if search:
        query += " AND LOWER(original_message) LIKE ?"
        params.append(f"%{search}%")
    if risk:
        query += " AND risk_level = ?"
        params.append(risk)
    if label:
        query += " AND prediction_label = ?"
        params.append(label)
    query += " ORDER BY created_at DESC LIMIT 200"
    scans = query_all(query, tuple(params))
    return render_template("app/history.html", scans=scans, search=search, risk=risk, label=label, json=json)

@main_bp.route("/analytics")
@login_required
def analytics():
    summary = query_one(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN prediction_label='Phishing' THEN 1 ELSE 0 END) AS phishing_count,
            SUM(CASE WHEN prediction_label='Legitimate' THEN 1 ELSE 0 END) AS legitimate_count,
            SUM(CASE WHEN risk_level='High' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN risk_level='Medium' THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN risk_level='Low' THEN 1 ELSE 0 END) AS low_count
        FROM scans WHERE user_id = ?
        """,
        (session["user_id"],),
    )
    recent = query_all(
        """
        SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count
        FROM scans WHERE user_id = ?
        GROUP BY substr(created_at, 1, 10)
        ORDER BY day DESC LIMIT 7
        """,
        (session["user_id"],),
    )
    recent = list(reversed(recent))
    metrics = get_metrics()
    return render_template("app/analytics.html", summary=summary, recent=recent, metrics=metrics)

@main_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = query_one("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        institution = (request.form.get("institution") or "").strip()
        bio = (request.form.get("bio") or "").strip()
        new_password = request.form.get("new_password") or ""
        execute(
            "UPDATE users SET full_name = ?, institution = ?, bio = ? WHERE id = ?",
            (full_name, institution, bio, session["user_id"]),
        )
        if new_password:
            if len(new_password) < 8:
                flash("New password must be at least 8 characters long.", "danger")
                return redirect(url_for("main.profile"))
            salt, hashed = pbkdf2_hash(new_password)
            execute("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?", (hashed, salt, session["user_id"]))
        session["user_name"] = full_name
        log_action(session["user_id"], "profile_update", "user", "info", "Profile was updated.")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("main.profile"))
    return render_template("app/profile.html", user=user)

@main_bp.route("/admin")
@admin_required
def admin_overview():
    stats = get_admin_stats()
    recent_users = query_all("SELECT * FROM users ORDER BY created_at DESC LIMIT 5")
    recent_logs = query_all("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 8")
    return render_template("admin/index.html", stats=stats, recent_users=recent_users, recent_logs=recent_logs)

@main_bp.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        action = request.form.get("action")
        user_id = int(request.form.get("user_id"))
        if action == "toggle_active":
            user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
            new_state = 0 if user["is_active"] else 1
            execute("UPDATE users SET is_active = ? WHERE id = ?", (new_state, user_id))
            log_action(session["user_id"], "toggle_user_status", "user", "warning", f"Set user #{user_id} active={new_state}.")
        elif action == "toggle_role":
            user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
            new_role = "admin" if user["role"] == "user" else "user"
            execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            log_action(session["user_id"], "toggle_user_role", "user", "warning", f"Changed user #{user_id} role to {new_role}.")
        flash("User updated successfully.", "success")
        return redirect(url_for("main.admin_users"))
    users = query_all("SELECT * FROM users ORDER BY created_at DESC")
    return render_template("admin/users.html", users=users)

@main_bp.route("/admin/scans")
@admin_required
def admin_scans():
    scans = query_all(
        """
        SELECT scans.*, users.full_name, users.email
        FROM scans
        JOIN users ON users.id = scans.user_id
        ORDER BY scans.created_at DESC LIMIT 250
        """
    )
    return render_template("admin/scans.html", scans=scans, json=json)

@main_bp.route("/admin/audit")
@admin_required
def admin_audit():
    logs = query_all(
        """
        SELECT audit_logs.*, users.full_name
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.actor_user_id
        ORDER BY audit_logs.created_at DESC LIMIT 300
        """
    )
    return render_template("admin/audit.html", logs=logs)

@main_bp.route("/admin/contacts")
@admin_required
def admin_contacts():
    contacts = query_all("SELECT * FROM contact_messages ORDER BY created_at DESC")
    return render_template("admin/contacts.html", contacts=contacts)

@main_bp.route("/admin/model")
@admin_required
def admin_model():
    metrics = get_metrics()
    training = query_all("SELECT * FROM training_runs ORDER BY trained_at DESC")
    return render_template("admin/model.html", metrics=metrics, training=training, json=json)
