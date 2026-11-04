#!/bin/bash
# Pulls the latest commits and restarts WebSSH.
# Usage: ./update.sh [pid-of-running-server]
# The web UI passes its own PID so a server started without start_services.sh is also restarted.
cd "$(dirname "$0")" || exit 1

exec >> update.log 2>&1
echo "=== Update started $(date '+%Y-%m-%d %H:%M:%S') ==="

SERVER_PID="${1:-}"
case "$SERVER_PID" in
    *[!0-9]*) SERVER_PID="" ;;
esac

# Let the web request that triggered the update finish first.
sleep 1

OLD_HEAD=$(git rev-parse HEAD) || exit 1
if ! git pull --ff-only; then
    echo "git pull failed; the running service was left untouched."
    exit 1
fi
NEW_HEAD=$(git rev-parse HEAD)
echo "Updated $OLD_HEAD -> $NEW_HEAD"

if ! git diff --quiet "$OLD_HEAD" "$NEW_HEAD" -- requirements.txt; then
    if [ -x "venv/bin/python" ]; then
        PYTHON_BIN="venv/bin/python"
    else
        PYTHON_BIN="python3"
    fi
    echo "requirements.txt changed; installing dependencies."
    if ! "$PYTHON_BIN" -m pip install -r requirements.txt; then
        echo "Dependency installation failed; the running service was left untouched."
        exit 1
    fi
fi

bash stop_services.sh

if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID"
    for _ in $(seq 1 20); do
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.5
    done
    kill -0 "$SERVER_PID" 2>/dev/null && kill -9 "$SERVER_PID"
fi

bash start_services.sh
STATUS=$?
echo "=== Update finished with status $STATUS ==="
exit $STATUS
