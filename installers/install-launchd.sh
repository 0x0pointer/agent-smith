#!/usr/bin/env bash
# Install (or remove) the launchd LaunchAgent that keeps the pentest-agent MCP
# SSE server (port 7778) alive across crashes, logout/login, and reboots.
#
# Without this, the SSE daemon is a bare `uvicorn.run()` with no supervisor:
# any exit leaves MCP dead until someone manually restarts it — which is why
# `session()/scan()/report()` kept dropping with "Unable to connect" after a
# restart. launchd KeepAlive turns it into a self-healing service.
#
# Usage: install-launchd.sh [install|uninstall|reload|status]
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="com.agent-smith.mcp-sse"
SRC_PLIST="$REPO_DIR/installers/$LABEL.plist"
DEST_DIR="$HOME/Library/LaunchAgents"
DEST_PLIST="$DEST_DIR/$LABEL.plist"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "launchd is macOS-only. On Linux use a systemd unit or supervisor instead." >&2
    exit 1
fi

_render() {
    mkdir -p "$DEST_DIR" "$REPO_DIR/logs"
    # Substitute the REPO_DIR placeholder with the real checkout path.
    sed "s#REPO_DIR#${REPO_DIR}#g" "$SRC_PLIST" > "$DEST_PLIST"
    echo "Rendered $DEST_PLIST"
}

_unload() {
    # bootout is the modern API; fall back to legacy unload for older macOS.
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null \
        || launchctl unload "$DEST_PLIST" 2>/dev/null || true
}

_load() {
    launchctl bootstrap "gui/$(id -u)" "$DEST_PLIST" 2>/dev/null \
        || launchctl load "$DEST_PLIST"
    launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true
}

case "${1:-install}" in
    install|reload)
        # Stop any manually-started daemon so launchd is the sole supervisor.
        "$REPO_DIR/installers/start-mcp-server.sh" stop 2>/dev/null || true
        _unload
        _render
        _load
        echo "Loaded $LABEL — waiting for port 7778..."
        for i in $(seq 1 20); do
            if curl -sf --max-time 1 http://127.0.0.1:7778/sse >/dev/null 2>&1; then
                echo "✓ MCP SSE server is up on 127.0.0.1:7778 (supervised by launchd)"
                exit 0
            fi
            sleep 0.5
        done
        echo "✗ Did not come up in time — check $REPO_DIR/logs/mcp_sse.log and logs/mcp_crash.log" >&2
        exit 1
        ;;
    uninstall)
        _unload
        rm -f "$DEST_PLIST"
        echo "Removed $LABEL (MCP SSE server is no longer supervised)"
        ;;
    status)
        if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
            echo "launchd job loaded:"
            launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -E "state =|pid =|last exit" || true
        else
            echo "launchd job NOT loaded"
        fi
        curl -sf --max-time 1 http://127.0.0.1:7778/sse >/dev/null 2>&1 \
            && echo "port 7778: UP" || echo "port 7778: DOWN"
        ;;
    *)
        echo "Usage: $0 [install|uninstall|reload|status]" >&2
        exit 1
        ;;
esac
