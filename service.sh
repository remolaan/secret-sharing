#!/bin/bash
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$APP_DIR/.app.pid"
LOG_FILE="$APP_DIR/app.log"
PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}
WORKERS=${WORKERS:-4}

open_firewall() {
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        if ! sudo -n firewall-cmd --query-port="$PORT/tcp" &>/dev/null; then
            echo "Opening port $PORT in firewall (needs sudo) ..."
            if sudo firewall-cmd --permanent --add-port="$PORT/tcp" 2>/dev/null && sudo firewall-cmd --reload 2>/dev/null; then
                echo "Port $PORT opened"
            else
                echo "WARNING: Could not open firewall. Run manually:"
                echo "  sudo firewall-cmd --permanent --add-port=$PORT/tcp && sudo firewall-cmd --reload"
            fi
        fi
    elif command -v ufw &>/dev/null && systemctl is-active ufw &>/dev/null; then
        if ! sudo -n ufw status 2>/dev/null | grep -q "$PORT/tcp"; then
            echo "Opening port $PORT in ufw (needs sudo) ..."
            if sudo ufw allow "$PORT/tcp" 2>/dev/null; then
                echo "Port $PORT opened"
            else
                echo "WARNING: Could not open firewall. Run manually:"
                echo "  sudo ufw allow $PORT/tcp"
            fi
        fi
    else
        echo "No firewall detected, skipping"
    fi
}

start() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Already running (PID $(cat "$PID_FILE"))"
        exit 0
    fi

    open_firewall

    echo "Starting PasswdShare on $HOST:$PORT ..."
    cd "$APP_DIR"
    nohup python3.12 -m gunicorn app:app \
        --bind "$HOST:$PORT" \
        --workers "$WORKERS" \
        --access-logfile "$LOG_FILE" \
        --error-logfile "$LOG_FILE" \
        --pid "$PID_FILE" \
        --daemon

    sleep 1
    if [ -f "$PID_FILE" ]; then
        echo "Started (PID $(cat "$PID_FILE"))"
    else
        echo "Failed to start. Check $LOG_FILE"
        exit 1
    fi
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "Not running"
        return 0
    fi

    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping (PID $PID) ..."
        kill "$PID"
        sleep 2
        if kill -0 "$PID" 2>/dev/null; then
            kill -9 "$PID"
        fi
        rm -f "$PID_FILE"
        echo "Stopped"
    else
        echo "Not running (stale PID file)"
        rm -f "$PID_FILE"
    fi
}

status() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Running (PID $(cat "$PID_FILE"))"
    else
        echo "Not running"
    fi
}

restart() {
    stop
    start
}

case "${1}" in
    start)   start ;;
    stop)    stop ;;
    restart) restart ;;
    status)  status ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
