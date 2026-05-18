#!/usr/bin/env bash
# Usage: start-mcp-server.sh [start|stop|restart|status]
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$REPO_DIR/logs/mcp_sse.pid"
LOG_FILE="$REPO_DIR/logs/mcp_sse.log"
PORT=7778

_is_running() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

case "${1:-start}" in
    start)
        if _is_running; then
            echo "MCP SSE server already running (PID $(cat "$PID_FILE"))"
            exit 0
        fi
        # Kill any stale process on the port
        lsof -ti tcp:"$PORT" | xargs kill -9 2>/dev/null || true
        mkdir -p "$REPO_DIR/logs"
        # Use the venv Python directly — avoids poetry setting a bad PYTHONPATH
        # that injects Homebrew site-packages before the venv's own packages.
        VENV_PYTHON="$(poetry -C "$REPO_DIR" env info --executable 2>/dev/null)"
        if [[ -z "$VENV_PYTHON" ]]; then
            echo "✗ Could not determine venv Python path — run 'poetry -C $REPO_DIR install' first"
            exit 1
        fi
        nohup env PYTHONPATH="$REPO_DIR" "$VENV_PYTHON" -m mcp_server --transport sse \
            --host 127.0.0.1 --port "$PORT" >> "$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        # Wait up to 8s for readiness
        for i in $(seq 1 16); do
            curl -sf --max-time 1 http://127.0.0.1:"$PORT"/sse > /dev/null 2>&1 && break
            sleep 0.5
        done
        if _is_running; then
            echo "✓ MCP SSE server running (PID $(cat "$PID_FILE")) on port $PORT"
        else
            echo "✗ MCP SSE server failed to start — check $LOG_FILE"
            exit 1
        fi
        ;;
    stop)
        if _is_running; then
            kill "$(cat "$PID_FILE")" 2>/dev/null
        fi
        rm -f "$PID_FILE"
        echo "MCP SSE server stopped"
        ;;
    restart)
        "$0" stop
        sleep 1
        "$0" start
        ;;
    status)
        if _is_running; then
            echo "running (PID $(cat "$PID_FILE"))"
        else
            echo "not running"
        fi
        ;;
    *)
        echo "Usage: $0 [start|stop|restart|status]"
        exit 1
        ;;
esac
