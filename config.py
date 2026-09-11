import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = os.path.join(BASE_DIR, "secrets.db")

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DEFAULT_TTL_HOURS = 168  # 7 days

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

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))
