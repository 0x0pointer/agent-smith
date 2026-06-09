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
        RUNNER="$REPO_DIR/installers/run-mcp-server.sh"
        if [[ ! -x "$RUNNER" ]]; then
            echo "✗ MCP runner is not executable — run 'chmod +x $RUNNER'"
            exit 1
        fi
        if ! "$RUNNER" --print-python >/dev/null; then
            echo "✗ Could not determine venv Python path — run the Codex installer first"
            exit 1
        fi
        nohup "$RUNNER" --transport sse \
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
