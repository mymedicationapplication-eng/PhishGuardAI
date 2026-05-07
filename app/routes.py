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

@main_bp.route("/about")
def about():
    return render_template("about.html")

@main_bp.route("/features")
def features():
    metrics = get_metrics()
    return render_template("features.html", metrics=metrics)

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
        try:
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
            flash(f"Analysis complete: {result['prediction_label']} detected with {result['confidence']:.1f}% confidence.", "success")
        except Exception as e:
            flash(f"Error analyzing message: {str(e)}", "danger")
            return render_template("app/scan.html", result=None, message=message)
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
        try:
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
            phishing_count = sum(1 for r in results if r["prediction_label"] == "Phishing")
            flash(f"Batch processing complete: {len(results)} messages analyzed, {phishing_count} phishing threats detected.", "success")
        except Exception as e:
            flash(f"Error processing batch file: {str(e)}", "danger")
            return render_template("app/batch.html", results=None)
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
            flash(f"User {'activated' if new_state else 'deactivated'} successfully.", "success")
        elif action == "toggle_role":
            user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
            new_role = "admin" if user["role"] == "user" else "user"
            execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            log_action(session["user_id"], "toggle_user_role", "user", "warning", f"Changed user #{user_id} role to {new_role}.")
            flash(f"User role changed to {new_role} successfully.", "success")
        return redirect(url_for("main.admin_users"))
    
    # Filtering
    q = (request.args.get("q") or "").strip().lower()
    role = (request.args.get("role") or "").strip()
    status = (request.args.get("status") or "").strip()
    
    query = "SELECT * FROM users WHERE 1=1"
    params = []
    
    if q:
        query += " AND (LOWER(full_name) LIKE ? OR LOWER(email) LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if role:
        query += " AND role = ?"
        params.append(role)
    if status:
        query += " AND is_active = ?"
        params.append(1 if status == "active" else 0)
    
    query += " ORDER BY created_at DESC"
    users = query_all(query, tuple(params))
    return render_template("admin/users.html", users=users)

@main_bp.route("/admin/scans")
@admin_required
def admin_scans():
    q = (request.args.get("q") or "").strip().lower()
    label = (request.args.get("label") or "").strip()
    risk = (request.args.get("risk") or "").strip()
    
    query = """
        SELECT scans.*, users.full_name, users.email
        FROM scans
        JOIN users ON users.id = scans.user_id
        WHERE 1=1
    """
    params = []
    
    if q:
        query += " AND (LOWER(scans.original_message) LIKE ? OR LOWER(users.full_name) LIKE ? OR LOWER(users.email) LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if label:
        query += " AND scans.prediction_label = ?"
        params.append(label)
    if risk:
        query += " AND scans.risk_level = ?"
        params.append(risk)
    
    query += " ORDER BY scans.created_at DESC LIMIT 250"
    scans = query_all(query, tuple(params))
    return render_template("admin/scans.html", scans=scans, json=json)

@main_bp.route("/admin/audit")
@admin_required
def admin_audit():
    q = (request.args.get("q") or "").strip().lower()
    severity = (request.args.get("severity") or "").strip()
    action = (request.args.get("action") or "").strip()
    
    query = """
        SELECT audit_logs.*, users.full_name
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.actor_user_id
        WHERE 1=1
    """
    params = []
    
    if q:
        query += " AND (LOWER(audit_logs.action_type) LIKE ? OR LOWER(audit_logs.description) LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if severity:
        query += " AND audit_logs.severity = ?"
        params.append(severity)
    if action:
        query += " AND audit_logs.action_type = ?"
        params.append(action)
    
    query += " ORDER BY audit_logs.created_at DESC LIMIT 300"
    logs = query_all(query, tuple(params))
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
    scan_count = query_one("SELECT COUNT(*) as count FROM scans")["count"]
    training_runs = query_all("SELECT * FROM training_runs ORDER BY trained_at DESC LIMIT 10")
    return render_template("admin/model.html", metrics=metrics, scan_count=scan_count, training_runs=training_runs, json=json)

@main_bp.route("/admin/model/retrain", methods=["POST"])
@admin_required
def admin_model_retrain():
    try:
        import pandas as pd
        import numpy as np
        from sklearn.model_selection import train_test_split
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.svm import SVC
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
        import joblib
        import os
        from datetime import datetime
        
        # Get form parameters
        data_source = request.form.get("data_source")
        algorithm = request.form.get("algorithm")
        test_split = float(request.form.get("test_split", 20)) / 100
        random_state = int(request.form.get("random_state", 42))
        max_features = int(request.form.get("max_features", 5000))
        backup_current = request.form.get("backup_current") == "on"
        
        # Start training run record
        training_id = execute(
            """
            INSERT INTO training_runs (algorithm, data_source, test_split, random_state, max_features, status, started_at)
            VALUES (?, ?, ?, ?, ?, 'running', ?)
            """,
            (algorithm, data_source, test_split, random_state, max_features, utc_now_iso())
        ).lastrowid
        
        # Prepare training data
        if data_source == "scan_data":
            # Use existing scan data
            scans = query_all(
                "SELECT original_message, prediction_label FROM scans WHERE original_message IS NOT NULL AND prediction_label IS NOT NULL"
            )
            if len(scans) < 100:
                raise Exception("Insufficient scan data for training. Need at least 100 records.")
            
            messages = [scan["original_message"] for scan in scans]
            labels = [1 if scan["prediction_label"] == "Phishing" else 0 for scan in scans]
            
        elif data_source == "upload_file":
            # Use uploaded file
            upload = request.files.get("training_file")
            if not upload or not upload.filename:
                raise Exception("Training file is required when using upload option.")
            
            # Read uploaded CSV
            df = pd.read_csv(upload)
            if "message" not in df.columns or "label" not in df.columns:
                raise Exception("CSV must have 'message' and 'label' columns.")
            
            messages = df["message"].tolist()
            labels = [1 if str(label).lower() in ["phishing", "phish", "1"] else 0 for label in df["label"]]
        
        # Backup current model if requested
        if backup_current:
            artifacts_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
            backup_dir = os.path.join(artifacts_dir, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if os.path.exists(os.path.join(artifacts_dir, "phishing_detector.joblib")):
                import shutil
                shutil.copy2(
                    os.path.join(artifacts_dir, "phishing_detector.joblib"),
                    os.path.join(backup_dir, f"phishing_detector_backup_{timestamp}.joblib")
                )
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            messages, labels, test_size=test_split, random_state=random_state, stratify=labels
        )
        
        # Vectorize text
        vectorizer = TfidfVectorizer(max_features=max_features, stop_words="english", lowercase=True)
        X_train_vec = vectorizer.fit_transform(X_train)
        X_test_vec = vectorizer.transform(X_test)
        
        # Select and train model
        if algorithm == "logistic_regression":
            model = LogisticRegression(random_state=random_state, max_iter=1000)
        elif algorithm == "random_forest":
            model = RandomForestClassifier(n_estimators=100, random_state=random_state)
        elif algorithm == "svm":
            model = SVC(probability=True, random_state=random_state)
        elif algorithm == "naive_bayes":
            model = MultinomialNB()
        else:
            raise Exception(f"Unknown algorithm: {algorithm}")
        
        # Train model
        model.fit(X_train_vec, y_train)
        
        # Make predictions
        y_pred = model.predict(X_test_vec)
        y_pred_proba = model.predict_proba(X_test_vec)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        # Save new model and vectorizer
        artifacts_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
        os.makedirs(artifacts_dir, exist_ok=True)
        
        model_data = {
            "model": model,
            "vectorizer": vectorizer,
            "algorithm": algorithm,
            "trained_at": utc_now_iso(),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "confusion_matrix": cm,
            "train_size": len(X_train),
            "test_size": len(X_test),
            "total_records": len(messages)
        }
        
        joblib.dump(model_data, os.path.join(artifacts_dir, "phishing_detector.joblib"))
        
        # Update metrics file
        metrics_data = {
            "model_type": algorithm.replace("_", " ").title(),
            "trained_at": utc_now_iso(),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "confusion_matrix": cm,
            "train_size": len(X_train),
            "test_size": len(X_test),
            "total_records": len(messages)
        }
        
        with open(os.path.join(artifacts_dir, "metrics.json"), "w") as f:
            json.dump(metrics_data, f, indent=2)
        
        # Update training run record
        execute(
            """
            UPDATE training_runs SET 
                status = 'completed',
                accuracy = ?,
                precision = ?,
                recall = ?,
                f1_score = ?,
                roc_auc = ?,
                confusion_matrix = ?,
                train_size = ?,
                test_size = ?,
                total_records = ?,
                trained_at = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (accuracy, precision, recall, f1, roc_auc, json.dumps(cm), 
             len(X_train), len(X_test), len(messages), utc_now_iso(), utc_now_iso(), training_id)
        )
        
        log_action(
            session["user_id"], 
            "model_retrain", 
            "model", 
            "warning", 
            f"Model retrained with {algorithm} algorithm. Accuracy: {accuracy:.3f}"
        )
        
        flash(
            f"Model retraining completed successfully! New accuracy: {accuracy:.1%}. "
            f"The updated model is now active and ready for use.", 
            "success"
        )
        
    except Exception as e:
        # Update training run as failed
        if 'training_id' in locals():
            execute(
                "UPDATE training_runs SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?",
                (str(e), utc_now_iso(), training_id)
            )
        
        log_action(
            session["user_id"], 
            "model_retrain_failed", 
            "model", 
            "error", 
            f"Model retraining failed: {str(e)}"
        )
        
        flash(f"Model retraining failed: {str(e)}", "danger")
    
    return redirect(url_for("main.admin_model"))

@main_bp.route("/admin/users/export/<format>")
@admin_required
def admin_users_export(format):
    users = query_all("SELECT * FROM users ORDER BY created_at DESC")
    
    if format == "excel":
        import pandas as pd
        from io import BytesIO
        
        data = [{
            "ID": u["id"],
            "Name": u["full_name"],
            "Email": u["email"],
            "Role": u["role"],
            "Status": "Active" if u["is_active"] else "Inactive",
            "Institution": u["institution"] or "",
            "Created": u["created_at"],
            "Last Login": u["last_login"] or "Never"
        } for u in users]
        
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Users')
        output.seek(0)
        
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"phishguard_users_{utc_now_iso()[:10]}.xlsx"
        )
    
    elif format == "pdf":
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from io import BytesIO
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph("<b>PhishGuard - User Management Report</b>", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Table data
        data = [["ID", "Name", "Email", "Role", "Status", "Created"]]
        for u in users:
            data.append([
                str(u["id"]),
                u["full_name"],
                u["email"],
                u["role"].capitalize(),
                "Active" if u["is_active"] else "Inactive",
                u["created_at"][:10]
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"phishguard_users_{utc_now_iso()[:10]}.pdf"
        )
    
    flash("Invalid export format.", "danger")
    return redirect(url_for("main.admin_users"))

@main_bp.route("/admin/scans/export/<format>")
@admin_required
def admin_scans_export(format):
    scans = query_all(
        """
        SELECT scans.*, users.full_name, users.email
        FROM scans
        JOIN users ON users.id = scans.user_id
        ORDER BY scans.created_at DESC LIMIT 1000
        """
    )
    
    if format == "excel":
        import pandas as pd
        from io import BytesIO
        
        data = [{
            "ID": s["id"],
            "User": s["full_name"],
            "Email": s["email"],
            "Message": s["original_message"][:100],
            "Prediction": s["prediction_label"],
            "Confidence": f"{s['confidence']:.2f}%",
            "Risk Level": s["risk_level"],
            "Risk Score": s["risk_score"],
            "Created": s["created_at"]
        } for s in scans]
        
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Scans')
        output.seek(0)
        
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"phishguard_scans_{utc_now_iso()[:10]}.xlsx"
        )
    
    elif format == "pdf":
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from io import BytesIO
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
        elements = []
        styles = getSampleStyleSheet()
        
        title = Paragraph("<b>PhishGuard - Scan Records Report</b>", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        data = [["ID", "User", "Prediction", "Confidence", "Risk", "Score", "Date"]]
        for s in scans[:100]:  # Limit to 100 for PDF
            data.append([
                str(s["id"]),
                s["full_name"],
                s["prediction_label"],
                f"{s['confidence']:.1f}%",
                s["risk_level"],
                str(s["risk_score"]),
                s["created_at"][:10]
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"phishguard_scans_{utc_now_iso()[:10]}.pdf"
        )
    
    flash("Invalid export format.", "danger")
    return redirect(url_for("main.admin_scans"))

@main_bp.route("/admin/contacts/export/<format>")
@admin_required
def admin_contacts_export(format):
    contacts = query_all("SELECT * FROM contact_messages ORDER BY created_at DESC")
    
    if format == "excel":
        import pandas as pd
        from io import BytesIO
        
        data = [{
            "ID": c["id"],
            "Name": c["full_name"],
            "Email": c["email"],
            "Subject": c["subject"] or "General inquiry",
            "Message": c["message"],
            "Submitted": c["created_at"]
        } for c in contacts]
        
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Contacts')
        output.seek(0)
        
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"phishguard_contacts_{utc_now_iso()[:10]}.xlsx"
        )
    
    elif format == "pdf":
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from io import BytesIO
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
        elements = []
        styles = getSampleStyleSheet()
        
        title = Paragraph("<b>PhishGuard - Contact Messages Report</b>", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        data = [["ID", "Name", "Email", "Subject", "Date"]]
        for c in contacts[:100]:
            data.append([
                str(c["id"]),
                c["full_name"],
                c["email"],
                (c["subject"] or "General")[:30],
                c["created_at"][:10]
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"phishguard_contacts_{utc_now_iso()[:10]}.pdf"
        )
    
    flash("Invalid export format.", "danger")
    return redirect(url_for("main.admin_contacts"))

@main_bp.route("/admin/audit/export/<format>")
@admin_required
def admin_audit_export(format):
    logs = query_all(
        """
        SELECT audit_logs.*, users.full_name
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.actor_user_id
        ORDER BY audit_logs.created_at DESC LIMIT 500
        """
    )
    
    if format == "excel":
        import pandas as pd
        from io import BytesIO
        
        data = [{
            "ID": log["id"],
            "Timestamp": log["created_at"],
            "Actor": log["full_name"] or "System",
            "Action": log["action_type"],
            "Target Type": log["target_type"],
            "Severity": log["severity"],
            "Description": log["description"]
        } for log in logs]
        
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Audit Log')
        output.seek(0)
        
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"phishguard_audit_{utc_now_iso()[:10]}.xlsx"
        )
    
    elif format == "pdf":
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from io import BytesIO
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
        elements = []
        styles = getSampleStyleSheet()
        
        title = Paragraph("<b>PhishGuard - Audit Log Report</b>", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        data = [["Timestamp", "Actor", "Action", "Severity", "Description"]]
        for log in logs[:100]:
            data.append([
                log["created_at"][:16],
                (log["full_name"] or "System")[:20],
                log["action_type"][:20],
                log["severity"],
                log["description"][:40]
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"phishguard_audit_{utc_now_iso()[:10]}.pdf"
        )
    
    flash("Invalid export format.", "danger")
    return redirect(url_for("main.admin_audit"))
