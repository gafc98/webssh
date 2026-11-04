#!/bin/bash
cd "$(dirname "$0")" || exit 1

PID_FILE="uvicorn.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "WebSSH is not running (no PID file found)."
    exit 0
fi

PID=$(cat "$PID_FILE")
case "$PID" in
    ''|*[!0-9]*)
        echo "Invalid PID in $PID_FILE."
        exit 1
        ;;
esac

if ! kill -0 "$PID" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "Removed stale PID file; WebSSH was not running."
    exit 0
fi

if ! kill "$PID" 2>/dev/null; then
    echo "Could not stop WebSSH (PID: $PID)."
    exit 1
fi

for _ in $(seq 1 20); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.5
done
if kill -0 "$PID" 2>/dev/null; then
    echo "WebSSH did not exit in time; forcing it to stop."
    kill -9 "$PID" 2>/dev/null
fi

rm -f "$PID_FILE"
echo "WebSSH stopped (PID: $PID)."
