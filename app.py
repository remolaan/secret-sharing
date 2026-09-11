import os
import sqlite3
import secrets
import string
import re
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for,
    abort, g, flash, session, make_response
)
from cryptography.fernet import Fernet
from markupsafe import escape

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

cipher = Fernet(config.ENCRYPTION_KEY.encode() if isinstance(config.ENCRYPTION_KEY, str) else config.ENCRYPTION_KEY)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


rate_limit_store = {}

def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            key = f"{ip}:{f.__name__}"
            if key not in rate_limit_store:
                rate_limit_store[key] = []
            rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window]
            if len(rate_limit_store[key]) >= max_requests:
                abort(429)
            rate_limit_store[key].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(config.DATABASE)
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
            view_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        )
    """)
    db.commit()
    db.close()


def generate_token(length=32):
    return secrets.token_urlsafe(length)


def encrypt_password(plain):
    if not plain:
        return ""
    return cipher.encrypt(plain.encode()).decode()


def decrypt_password(enc):
    if not enc:
        return ""
    return cipher.decrypt(enc.encode()).decode()


def sanitize_input(text, max_length=500):
    text = text.strip()[:max_length]
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


@app.route("/")
@rate_limit(max_requests=30, window=60)
def index():
    return render_template("create.html")


@app.route("/create", methods=["POST"])
@rate_limit(max_requests=30, window=60)
def create_secret():
    root_user = sanitize_input(request.form.get("root_user", ""), 100)
    root_pass = sanitize_input(request.form.get("root_pass", ""), 200)
    user_user = sanitize_input(request.form.get("user_user", ""), 100)
    user_pass = sanitize_input(request.form.get("user_pass", ""), 200)
    note = sanitize_input(request.form.get("note", ""), 1000)
    created_by = sanitize_input(request.form.get("created_by", ""), 200)
    ttl_hours = request.form.get("ttl_hours", config.DEFAULT_TTL_HOURS, type=int)
    max_views = request.form.get("max_views", 1, type=int)

    if not root_user or not root_pass:
        flash("Root username and password are required.", "error")
        return redirect(url_for("index"))

    ttl_hours = max(1, min(ttl_hours, 720))
    max_views = max(1, min(max_views, 10))

    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)

    db = get_db()
    db.execute(
        """INSERT INTO secrets
           (token, root_user, root_pass_enc, user_user, user_pass_enc, note, created_by, expires_at, max_views)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            token,
            root_user,
            encrypt_password(root_pass),
            user_user,
            encrypt_password(user_pass),
            note,
            created_by,
            expires_at.isoformat(),
            max_views,
        ),
    )
    db.commit()

    share_url = request.host_url.rstrip("/") + "/s/" + token
    return render_template("created.html", share_url=share_url, expires_at=expires_at, max_views=max_views)


@app.route("/s/<token>")
@rate_limit(max_requests=60, window=60)
def reveal_secret(token):
    if not re.match(r'^[A-Za-z0-9_-]+$', token):
        abort(404)

    db = get_db()
    row = db.execute(
        "SELECT * FROM secrets WHERE token = ? AND is_active = 1", (token,)
    ).fetchone()

    if not row:
        return render_template("expired.html", reason="not_found"), 404

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        db.execute("UPDATE secrets SET is_active = 0 WHERE token = ?", (token,))
        db.commit()
        return render_template("expired.html", reason="expired"), 410

    view_count = row["view_count"] + 1
    max_views = row["max_views"]

    if view_count > max_views:
        db.execute("UPDATE secrets SET is_active = 0 WHERE token = ?", (token,))
        db.commit()
        return render_template("expired.html", reason="max_views"), 410

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    db.execute("UPDATE secrets SET view_count = ? WHERE token = ?", (view_count, token))
    db.commit()

    app.logger.info(f"Secret viewed: token={token[:8]}... ip={client_ip} view={view_count}/{max_views}")

    secret = {
        "root_user": row["root_user"],
        "root_pass": decrypt_password(row["root_pass_enc"]),
        "user_user": row["user_user"],
        "user_pass": decrypt_password(row["user_pass_enc"]),
        "note": row["note"],
        "expires_at": expires_at,
        "token": token,
        "view_count": view_count,
        "max_views": max_views,
    }

    resp = make_response(render_template("reveal.html", secret=secret))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/api/secrets", methods=["GET"])
@rate_limit(max_requests=20, window=60)
def list_secrets():
    db = get_db()
    rows = db.execute(
        "SELECT token, root_user, user_user, created_by, created_at, expires_at, view_count, max_views FROM secrets WHERE is_active = 1 ORDER BY created_at DESC"
    ).fetchall()
    return {"secrets": [dict(r) for r in rows]}


@app.route("/delete/<token>", methods=["POST"])
@rate_limit(max_requests=30, window=60)
def delete_secret(token):
    db = get_db()
    db.execute("UPDATE secrets SET is_active = 0 WHERE token = ?", (token,))
    db.commit()
    flash("Secret deleted.", "success")
    return redirect(url_for("index"))


@app.errorhandler(429)
def rate_limited(e):
    return render_template("expired.html", reason="rate_limit"), 429


@app.before_request
def ensure_db():
    if not hasattr(app, "_db_initialized"):
        init_db()
        app._db_initialized = True


@app.before_request
def cleanup_rate_limits():
    now = time.time()
    expired = [k for k, v in rate_limit_store.items() if now - max(v) > 300]
    for k in expired:
        del rate_limit_store[k]


if __name__ == "__main__":
    init_db()
    app.run(host=config.HOST, port=config.PORT, debug=True)
