#!/usr/bin/env bash
# Usage: start-mcp-server.sh [start|stop|restart|status]
#
# The MCP server is normally supervised by the launchd job
# com.agent-smith.mcp-sse (KeepAlive=true, ThrottleInterval=10). When that job
# is loaded this script DELEGATES every lifecycle op to launchctl — it must
# NEVER start a second, self-managed nohup instance, because two supervisors
# binding the same port (7778) fight: whichever loses the bind exits 1 and
# launchd respawns it every 10s forever (the SESSION_START / "address already
# in use" crash-loop). The old `start` even `kill -9`'d the port first, which
# actively killed launchd's instance and kicked off the fight.
#
# On Linux the same role is played by the systemd USER unit agent-smith-mcp
# (Restart=always, RestartSec=10) and the same rule applies: delegate to
# systemctl --user, never start a competing nohup instance.
#
# Only when NEITHER supervisor is managing the server (a plain dev checkout with
# no job/unit loaded) does this fall back to a self-managed nohup process.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$REPO_DIR/logs/mcp_sse.pid"
LOG_FILE="$REPO_DIR/logs/mcp_sse.log"
PORT=7778
LAUNCHD_LABEL="com.agent-smith.mcp-sse"
LAUNCHD_TARGET="gui/$(id -u)/$LAUNCHD_LABEL"

_launchd_loaded() {
    command -v launchctl >/dev/null 2>&1 && launchctl list "$LAUNCHD_LABEL" >/dev/null 2>&1
}
_launchd_pid() { launchctl list "$LAUNCHD_LABEL" 2>/dev/null | sed -n 's/.*"PID" = \([0-9][0-9]*\).*/\1/p'; }

SYSTEMD_UNIT="agent-smith-mcp.service"

# `systemctl --user` needs a live user D-Bus session; absent in many containers,
# `ssh host cmd` invocations and minimal WSL distros. `systemctl --user cat` is
# the existence check — list-unit-files exits 0 even when it matches nothing.
_systemd_loaded() {
    command -v systemctl >/dev/null 2>&1 \
        && systemctl --user show-environment >/dev/null 2>&1 \
        && systemctl --user cat "$SYSTEMD_UNIT" >/dev/null 2>&1
}
_systemd_pid() {
    local pid
    pid="$(systemctl --user show -p MainPID --value "$SYSTEMD_UNIT" 2>/dev/null)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && echo "$pid"
}

_is_running() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

_clear_self_managed() {
    # A stale self-managed nohup instance would still hold port 7778 and make the
    # supervised instance crash-loop on "address already in use". Clear it.
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Clearing stale self-managed instance (PID $(cat "$PID_FILE")) so the supervisor owns the port"
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
}

# ── systemd --user path (Linux production default) ──────────────────────────
if _systemd_loaded; then
    _clear_self_managed
    case "${1:-start}" in
        start)
            systemctl --user start "$SYSTEMD_UNIT"
            echo "✓ MCP SSE server started via systemd ($SYSTEMD_UNIT)"
            ;;
        restart)
            systemctl --user restart "$SYSTEMD_UNIT"
            echo "✓ MCP SSE server restarted via systemd ($SYSTEMD_UNIT)"
            ;;
        stop)
            # Unlike launchd KeepAlive, an explicit systemd stop is honoured —
            # Restart=always does not fight it. Re-enable with `start`.
            systemctl --user stop "$SYSTEMD_UNIT"
            echo "✓ MCP SSE server stopped (systemd will not respawn it until 'start')"
            ;;
        status)
            pid="$(_systemd_pid)"
            if [[ -n "$pid" ]]; then
                echo "running under systemd (PID $pid)"
            else
                echo "systemd-managed but not currently running — systemctl --user status $SYSTEMD_UNIT; check $LOG_FILE"
            fi
            ;;
        *)
            echo "Usage: $0 [start|stop|restart|status]"; exit 1
            ;;
    esac
    exit 0
fi

# ── launchd-managed path (production default) — thin launchctl wrapper ──────
if _launchd_loaded; then
    _clear_self_managed
    case "${1:-start}" in
        start)
            launchctl kickstart "$LAUNCHD_TARGET" >/dev/null 2>&1 || true
            echo "✓ MCP SSE server start requested via launchd ($LAUNCHD_LABEL)"
            ;;
        restart)
            # kickstart -k cleanly kills the running instance and starts a fresh
            # one — launchd hands off the port with no fight.
            launchctl kickstart -k "$LAUNCHD_TARGET" >/dev/null 2>&1 || true
            echo "✓ MCP SSE server restarted via launchd (kickstart -k)"
            ;;
        stop)
            echo "MCP SSE server is launchd-managed (KeepAlive=true) — a plain kill"
            echo "just triggers an immediate respawn. To actually stop it:"
            echo "  launchctl bootout $LAUNCHD_TARGET   # disables self-heal until reload"
            ;;
        status)
            pid="$(_launchd_pid)"
            if [[ -n "$pid" ]]; then
                echo "running under launchd (PID $pid)"
            else
                echo "launchd-managed but not currently running — check $LOG_FILE"
            fi
            ;;
        *)
            echo "Usage: $0 [start|stop|restart|status]"; exit 1
            ;;
    esac
    exit 0
fi

# ── self-managed fallback (no launchd job / systemd unit loaded — dev only) ─
case "${1:-start}" in
    start)
        if _is_running; then
            echo "MCP SSE server already running (PID $(cat "$PID_FILE"))"
            exit 0
        fi
        # Safe here: with no supervisor loaded there is nothing to fight.
        # lsof is absent on minimal Linux images — fall back to ss, then fuser.
        if command -v lsof >/dev/null 2>&1; then
            lsof -ti tcp:"$PORT" | xargs -r kill -9 2>/dev/null || true
        elif command -v ss >/dev/null 2>&1; then
            ss -ltnpH "sport = :$PORT" 2>/dev/null \
                | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u \
                | xargs -r kill -9 2>/dev/null || true
        elif command -v fuser >/dev/null 2>&1; then
            fuser -k -n tcp "$PORT" >/dev/null 2>&1 || true
        fi
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
