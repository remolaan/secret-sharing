import os
import secrets
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DATABASE = os.path.join(BASE_DIR, "secrets.db")

# Flask session signing key. Set SECRET_KEY in the environment in production
# so sessions survive restarts and aren't tied to a value generated on the fly.
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DEFAULT_TTL_HOURS = 168  # 7 days

# Fernet key used to encrypt credentials at rest. MUST be set via environment
# variable in production (e.g. from a secrets manager / KMS). Falling back to
# a file on disk is only for local dev convenience.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    key_file = os.path.join(BASE_DIR, ".encryption_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            ENCRYPTION_KEY = f.read().strip()
    else:
        from cryptography.fernet import Fernet
        ENCRYPTION_KEY = Fernet.generate_key().decode()
        with open(key_file, "w") as f:
            f.write(ENCRYPTION_KEY)
        os.chmod(key_file, 0o600)

# Bootstrap admin account, created on first run only if the users table is
# empty. Change the password immediately after first login.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # if unset, a random one is generated and logged once

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))

# Set to "0" only for local dev over plain HTTP. Always "1" in production
# (requires the app to actually be served over HTTPS, e.g. behind a
# reverse proxy that terminates TLS).
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"

DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
