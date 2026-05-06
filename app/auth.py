from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from .db import query_one, execute, log_action
from .text_utils import pbkdf2_hash, verify_password, utc_now_iso

auth_bp = Blueprint("auth", __name__)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login"))
        if session.get("role") != "admin":
            flash("Administrator access is required.", "danger")
            return redirect(url_for("main.dashboard"))
        return view(*args, **kwargs)
    return wrapped

@auth_bp.before_app_request
def attach_current_user():
    from flask import g
    g.current_user = None
    user_id = session.get("user_id")
    if user_id:
        g.current_user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = query_one("SELECT * FROM users WHERE email = ?", (email,))
        if not user:
            flash("No account found with that email.", "danger")
            return render_template("auth/login.html")
        if not user["is_active"]:
            flash("This account is currently disabled.", "danger")
            return render_template("auth/login.html")
        if not verify_password(password, user["password_salt"], user["password_hash"]):
            flash("Invalid email or password.", "danger")
            log_action(user["id"], "login_failed", "auth", "warning", "Failed login attempt.")
            return render_template("auth/login.html")
        session.clear()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["user_name"] = user["full_name"]
        execute("UPDATE users SET last_login = ? WHERE id = ?", (utc_now_iso(), user["id"]))
        log_action(user["id"], "login", "auth", "info", "User logged in.")
        flash(f"Welcome back, {user['full_name'].split()[0]}!", "success")
        return redirect(url_for("main.dashboard"))
    return render_template("auth/login.html")

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        institution = (request.form.get("institution") or "").strip()
        if not full_name or not email or len(password) < 8:
            flash("Please fill in all required fields. Password must be at least 8 characters.", "danger")
            return render_template("auth/register.html")
        existing = query_one("SELECT id FROM users WHERE email = ?", (email,))
        if existing:
            flash("An account with this email already exists.", "warning")
            return render_template("auth/register.html")
        salt, hashed = pbkdf2_hash(password)
        cur = execute(
            """
            INSERT INTO users (full_name, email, password_hash, password_salt, role, institution, bio, is_active, created_at)
            VALUES (?, ?, ?, ?, 'user', ?, '', 1, ?)
            """,
            (full_name, email, hashed, salt, institution, utc_now_iso()),
        )
        log_action(cur.lastrowid, "register", "user", "info", f"New account created for {email}.")
        flash("Account created successfully. You can sign in now.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html")

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        new_password = request.form.get("new_password") or ""
        if len(new_password) < 8:
            flash("New password must be at least 8 characters long.", "danger")
            return render_template("auth/forgot_password.html")
        user = query_one("SELECT * FROM users WHERE email = ?", (email,))
        if not user:
            flash("No account found for that email.", "danger")
            return render_template("auth/forgot_password.html")
        salt, hashed = pbkdf2_hash(new_password)
        execute("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?", (hashed, salt, user["id"]))
        log_action(user["id"], "password_reset", "user", "warning", "Password was reset through the reset screen.")
        flash("Password updated. Please sign in with your new password.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot_password.html")

@auth_bp.route("/logout")
@login_required
def logout():
    user_id = session.get("user_id")
    session.clear()
    log_action(user_id, "logout", "auth", "info", "User logged out.")
    flash("You have been signed out.", "info")
    return redirect(url_for("main.landing"))
