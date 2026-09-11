#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Activate venv
source .venv/bin/activate 2>/dev/null || true

# Load env
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

exec python3 app.py
