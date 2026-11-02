#!/bin/bash
cd "$(dirname "$0")" || exit 1

PID_FILE="uvicorn.pid"
LOG_FILE="uvicorn.log"
UVICORN_PATTERN="[u]vicorn app:app --host 127.0.0.1 --port 8000"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "WebSSH is already running (PID: $PID)."
        exit 0
    fi
    rm -f "$PID_FILE"
fi

RUNNING_PID=$(pgrep -f "$UVICORN_PATTERN" | head -n 1)
if [ -n "$RUNNING_PID" ]; then
    echo "$RUNNING_PID" > "$PID_FILE"
    echo "WebSSH is already running (PID: $RUNNING_PID)."
    exit 0
fi

if [ -x "venv/bin/python" ]; then
    PYTHON_BIN="$(pwd)/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
else
    echo "Python 3 was not found. Install Python 3 or create the venv first."
    exit 1
fi

WEBSSH_COOKIE_SECURE=false nohup "$PYTHON_BIN" -m uvicorn app:app \
    --host 127.0.0.1 --port 8000 > "$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"

sleep 1
if kill -0 "$PID" 2>/dev/null; then
    echo "WebSSH started at http://127.0.0.1:8000 (PID: $PID)."
    echo "Logs are writing to $LOG_FILE."
else
    rm -f "$PID_FILE"
    echo "WebSSH failed to start. See $LOG_FILE for details."
    exit 1
fi
