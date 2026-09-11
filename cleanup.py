"""Run via cron (e.g. every 15 min) as a backstop in case the app-triggered
purge never fires for a given expired row (no traffic hits it).

    */15 * * * * /path/to/venv/bin/python /path/to/secret-sharing/cleanup.py
"""
import sqlite3
from datetime import datetime
import config

if __name__ == "__main__":
    db = sqlite3.connect(config.DATABASE)
    cur = db.execute("DELETE FROM secrets WHERE expires_at < ?", (datetime.utcnow().isoformat(),))
    db.commit()
    print(f"Purged {cur.rowcount} expired secret(s).")
    db.close()
