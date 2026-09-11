#!/bin/bash
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$APP_DIR/.app.pid"
LOG_FILE="$APP_DIR/app.log"
PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}

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
        else
            echo "Port $PORT already open"
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

close_firewall() {
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        if sudo -n firewall-cmd --query-port="$PORT/tcp" &>/dev/null; then
            echo "Closing port $PORT in firewall (needs sudo) ..."
            if sudo firewall-cmd --permanent --remove-port="$PORT/tcp" 2>/dev/null && sudo firewall-cmd --reload 2>/dev/null; then
                echo "Port $PORT closed"
            else
                echo "WARNING: Could not close firewall. Run manually:"
                echo "  sudo firewall-cmd --permanent --remove-port=$PORT/tcp && sudo firewall-cmd --reload"
            fi
        else
            echo "Port $PORT not open"
        fi
    elif command -v ufw &>/dev/null && systemctl is-active ufw &>/dev/null; then
        if sudo -n ufw status 2>/dev/null | grep -q "$PORT/tcp"; then
            echo "Closing port $PORT in ufw (needs sudo) ..."
            if sudo ufw delete allow "$PORT/tcp" 2>/dev/null; then
                echo "Port $PORT closed"
            else
                echo "WARNING: Could not close firewall. Run manually:"
                echo "  sudo ufw delete allow $PORT/tcp"
            fi
        fi
    fi
}

start() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Already running (PID $(cat "$PID_FILE"))"
        exit 0
    fi

    open_firewall

    echo "Starting Secret Share on $HOST:$PORT ..."
    cd "$APP_DIR"
    source .venv/bin/activate 2>/dev/null || true

    if [ -f .env ]; then
        set -a
        source .env
        set +a
    fi

    nohup python3 app.py > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    sleep 2
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Started (PID $(cat "$PID_FILE"))"
    else
        echo "Failed to start. Check $LOG_FILE"
        exit 1
    fi
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "Not running"
        close_firewall
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

    close_firewall
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
    open)    open_firewall ;;
    close)   close_firewall ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|open|close}"
        echo ""
        echo "  start    - Start the app and open firewall port"
        echo "  stop     - Stop the app"
        echo "  restart  - Restart the app"
        echo "  status   - Check if app is running"
        echo "  open     - Open firewall port $PORT only"
        echo "  close    - Close firewall port $PORT only"
        exit 1
        ;;
esac
