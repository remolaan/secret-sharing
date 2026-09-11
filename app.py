import os
import sqlite3
import secrets
import re
import time
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for,
    abort, g, flash, session, make_response
)
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE

cipher = Fernet(config.ENCRYPTION_KEY.encode() if isinstance(config.ENCRYPTION_KEY, str) else config.ENCRYPTION_KEY)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------------------------------------------------------------------------
# Rate limiting (in-memory; fine for a single-process deployment, swap for
# Redis if you run multiple workers)
# ---------------------------------------------------------------------------

rate_limit_store = {}


def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            key = f"{ip}:{f.__name__}"
            bucket = rate_limit_store.setdefault(key, [])
            bucket[:] = [t for t in bucket if now - t < window]
            if len(bucket) >= max_requests:
                abort(429)
            bucket.append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


@app.before_request
def cleanup_rate_limits():
    now = time.time()
    for k in [k for k, v in rate_limit_store.items() if not v or now - max(v) > 300]:
        del rate_limit_store[k]


# ---------------------------------------------------------------------------
# CSRF protection (lightweight, session-bound token)
# ---------------------------------------------------------------------------

def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def validate_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not secrets.compare_digest(submitted, expected):
        abort(400, description="Invalid or missing CSRF token.")


app.jinja_env.globals["csrf_token"] = csrf_token


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(config.DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Rows are hard-deleted on expiry / max-views / revoke, so "presence in
    # this table" always means "currently active" -- no is_active flag to
    # forget to check.
    db.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            root_user TEXT,
            root_pass_enc TEXT,
            user_user TEXT,
            user_pass_enc TEXT,
            note TEXT,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            max_views INTEGER DEFAULT 1,
            view_count INTEGER DEFAULT 0
        )
    """)
    db.commit()

    row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row["c"] == 0:
        password = config.ADMIN_PASSWORD or secrets.token_urlsafe(12)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (config.ADMIN_USERNAME, generate_password_hash(password)),
        )
        db.commit()
        if not config.ADMIN_PASSWORD:
            logging.warning(
                "No ADMIN_PASSWORD set. Created bootstrap admin '%s' with "
                "generated password: %s  -- log in and change it, this is "
                "only printed once.", config.ADMIN_USERNAME, password
            )
    db.close()


def purge_expired():
    """Hard-delete any row past its expiry. Cheap enough to run on every
    dashboard/reveal hit; also exposed as a manual button and can be called
    from a cron job via cleanup.py for belt-and-suspenders."""
    db = get_db()
    db.execute("DELETE FROM secrets WHERE expires_at < ?", (datetime.utcnow().isoformat(),))
    db.commit()


# ---------------------------------------------------------------------------
# Crypto / sanitization helpers
# ---------------------------------------------------------------------------

def encrypt_password(plain):
    if not plain:
        return ""
    return cipher.encrypt(plain.encode()).decode()


def decrypt_password(enc):
    if not enc:
        return ""
    return cipher.decrypt(enc.encode()).decode()


def sanitize_input(text, max_length=500):
    text = (text or "").strip()[:max_length]
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text


def generate_token(length=32):
    return secrets.token_urlsafe(length)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_requests=8, window=300)
def login():
    if request.method == "POST":
        validate_csrf()
        username = sanitize_input(request.form.get("username", ""), 100)
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            next_url = request.args.get("next")
            return redirect(next_url if next_url and next_url.startswith("/") else url_for("dashboard"))
        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    validate_csrf()
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard (staff-only: create + manage links)
# ---------------------------------------------------------------------------

@app.route("/")
def root():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    purge_expired()
    db = get_db()
    rows = db.execute(
        """SELECT token, root_user, user_user, note, created_by, created_at,
                  expires_at, view_count, max_views
           FROM secrets ORDER BY created_at DESC"""
    ).fetchall()
    secrets_list = []
    for r in rows:
        d = dict(r)
        d["share_url"] = request.host_url.rstrip("/") + "/s/" + d["token"]
        secrets_list.append(d)
    return render_template("dashboard.html", secrets=secrets_list, username=session.get("username"))


@app.route("/create", methods=["POST"])
@login_required
@rate_limit(max_requests=30, window=60)
def create_secret():
    validate_csrf()
    root_user = sanitize_input(request.form.get("root_user", ""), 100)
    root_pass = sanitize_input(request.form.get("root_pass", ""), 200)
    user_user = sanitize_input(request.form.get("user_user", ""), 100)
    user_pass = sanitize_input(request.form.get("user_pass", ""), 200)
    note = sanitize_input(request.form.get("note", ""), 1000)
    created_by = sanitize_input(request.form.get("created_by", ""), 200) or session.get("username", "")

    ttl_hours = request.form.get("ttl_hours", config.DEFAULT_TTL_HOURS, type=int) or config.DEFAULT_TTL_HOURS
    max_views = request.form.get("max_views", 1, type=int) or 1

    if not root_user or not root_pass:
        flash("Root username and password are required.", "error")
        return redirect(url_for("dashboard"))

    ttl_hours = max(1, min(ttl_hours, 720))
    max_views = max(1, min(max_views, 10))

    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)

    db = get_db()
    db.execute(
        """INSERT INTO secrets
           (token, root_user, root_pass_enc, user_user, user_pass_enc, note, created_by, expires_at, max_views)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (token, root_user, encrypt_password(root_pass), user_user, encrypt_password(user_pass),
         note, created_by, expires_at.isoformat(), max_views),
    )
    db.commit()

    share_url = request.host_url.rstrip("/") + "/s/" + token
    return render_template("created.html", share_url=share_url, expires_at=expires_at, max_views=max_views)


@app.route("/secrets/<token>/revoke", methods=["POST"])
@login_required
@rate_limit(max_requests=30, window=60)
def revoke_secret(token):
    validate_csrf()
    db = get_db()
    db.execute("DELETE FROM secrets WHERE token = ?", (token,))
    db.commit()
    flash("Link revoked and permanently deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/secrets/cleanup", methods=["POST"])
@login_required
def cleanup_now():
    validate_csrf()
    purge_expired()
    flash("Expired links purged.", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Client-facing reveal flow (no login -- gated by the token + explicit
# consent instead). GET never consumes a view, so link-scanners/email
# security crawlers that pre-fetch URLs can't burn it before the real
# recipient opens it. Only the confirmed POST consumes a view.
# ---------------------------------------------------------------------------

def _fetch_active_secret(db, token):
    row = db.execute("SELECT * FROM secrets WHERE token = ?", (token,)).fetchone()
    if not row:
        return None, ("not_found", 404)
    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        db.execute("DELETE FROM secrets WHERE token = ?", (token,))
        db.commit()
        return None, ("expired", 410)
    if row["view_count"] >= row["max_views"]:
        db.execute("DELETE FROM secrets WHERE token = ?", (token,))
        db.commit()
        return None, ("max_views", 410)
    return row, None


@app.route("/s/<token>", methods=["GET"])
@rate_limit(max_requests=60, window=60)
def reveal_confirm(token):
    if not re.match(r"^[A-Za-z0-9_-]+$", token):
        abort(404)
    db = get_db()
    row, err = _fetch_active_secret(db, token)
    if err:
        reason, status = err
        return render_template("expired.html", reason=reason), status
    return render_template(
        "reveal_confirm.html",
        token=token,
        note=row["note"],
        expires_at=datetime.fromisoformat(row["expires_at"]),
        views_left=row["max_views"] - row["view_count"],
        max_views=row["max_views"],
    )


@app.route("/s/<token>", methods=["POST"])
@rate_limit(max_requests=20, window=60)
def reveal_secret(token):
    if not re.match(r"^[A-Za-z0-9_-]+$", token):
        abort(404)
    validate_csrf()
    if request.form.get("accept") != "on":
        flash("You must confirm you understand before the credential can be shown.", "error")
        return redirect(url_for("reveal_confirm", token=token))

    db = get_db()
    row, err = _fetch_active_secret(db, token)
    if err:
        reason, status = err
        return render_template("expired.html", reason=reason), status

    view_count = row["view_count"] + 1
    max_views = row["max_views"]

    secret = {
        "root_user": row["root_user"],
        "root_pass": decrypt_password(row["root_pass_enc"]),
        "user_user": row["user_user"],
        "user_pass": decrypt_password(row["user_pass_enc"]),
        "note": row["note"],
        "view_count": view_count,
        "max_views": max_views,
    }

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if view_count >= max_views:
        # last permitted view: show it once, then it is gone for good
        db.execute("DELETE FROM secrets WHERE token = ?", (token,))
    else:
        db.execute("UPDATE secrets SET view_count = ? WHERE token = ?", (view_count, token))
    db.commit()

    logging.info("Secret viewed: token=%s... ip=%s view=%s/%s", token[:8], client_ip, view_count, max_views)

    resp = make_response(render_template("reveal.html", secret=secret))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(429)
def rate_limited(e):
    return render_template("expired.html", reason="rate_limit"), 429


@app.errorhandler(400)
def bad_request(e):
    return render_template("expired.html", reason="bad_request"), 400


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
else:
    # also initialize when run under gunicorn/wsgi
    init_db()
