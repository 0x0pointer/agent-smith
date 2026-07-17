#!/usr/bin/env bash
# change-mcp-port.sh
# Update the local MCP SSE port when the default port is already in use.
#
# What this updates:
# 1) launchd LaunchAgent plist: ~/Library/LaunchAgents/com.agent-smith.mcp-sse.plist
# 2) Claude Code MCP registration (if claude CLI is installed)
# 3) opencode MCP registration in ~/.config/opencode/opencode.json (if present)
#
# Usage:
#   installers/change-mcp-port.sh <new_port>
# Example:
#   installers/change-mcp-port.sh 7789

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="com.agent-smith.mcp-sse"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
OPENCODE_CONFIG="$HOME/.config/opencode/opencode.json"
NEW_PORT="${1:-}"

if [[ -z "$NEW_PORT" ]]; then
    echo "Usage: $0 <new_port>"
    exit 1
fi

if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || (( NEW_PORT < 1 || NEW_PORT > 65535 )); then
    echo "Invalid port: $NEW_PORT (must be an integer from 1 to 65535)"
    exit 1
fi

if [[ ! -f "$PLIST_PATH" ]]; then
    echo "LaunchAgent plist not found: $PLIST_PATH"
    echo "Install first, then run this script."
    exit 1
fi

if lsof -n -iTCP:"$NEW_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    listeners="$(lsof -n -tiTCP:"$NEW_PORT" -sTCP:LISTEN | tr '\n' ' ')"
    keep_going=false
    for pid in $listeners; do
        cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
        if [[ "$cmd" == *"mcp_server"* ]] || [[ "$cmd" == *"run-mcp-server.sh"* ]]; then
            keep_going=true
            break
        fi
    done

    if [[ "$keep_going" != true ]]; then
        echo "Port $NEW_PORT is already in use. Pick a different port."
        lsof -n -iTCP:"$NEW_PORT" -sTCP:LISTEN || true
        exit 1
    fi
fi

extract_plist_port() {
    local plist="$1"
    awk '
        /<string>--port<\/string>/ { want = 1; next }
        want && match($0, /<string>[0-9]+<\/string>/) {
            s = substr($0, RSTART, RLENGTH)
            gsub(/<string>|<\/string>/, "", s)
            print s
            exit
        }
    ' "$plist"
}

rewrite_plist_port() {
    local plist="$1"
    local new_port="$2"
    local tmp
    tmp="$(mktemp)"

    awk -v p="$new_port" '
        {
            if (want && match($0, /<string>[0-9]+<\/string>/)) {
                $0 = "        <string>" p "</string>"
                want = 0
                changed = 1
            }
            if ($0 ~ /<string>--port<\/string>/) {
                want = 1
            }
            print
        }
        END {
            if (!changed) {
                exit 2
            }
        }
    ' "$plist" > "$tmp"

    mv "$tmp" "$plist"
}

rewrite_installer_ports() {
    local new_port="$1"
    local old_port="$2"
    local f
    local files=(
        "$REPO_DIR/installers/start-mcp-server.sh"
        "$REPO_DIR/installers/install.sh"
        "$REPO_DIR/installers/install_opencode.sh"
        "$REPO_DIR/installers/install-launchd.sh"
        "$REPO_DIR/installers/com.agent-smith.mcp-sse.plist"
    )

    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue

        NEW_PORT="$new_port" OLD_PORT="$old_port" perl -0pi -e '
            my $new = $ENV{"NEW_PORT"};
            my $old = $ENV{"OLD_PORT"};
            s/\b7778\b/$new/g;
            if (defined $old && $old ne q{} && $old ne $new) {
                s/\b\Q$old\E\b/$new/g;
            }
        ' "$f"
    done

    echo "Updated installer scripts/templates to use port ${new_port}"
}

OLD_PORT="$(extract_plist_port "$PLIST_PATH" || true)"
if [[ -z "$OLD_PORT" ]]; then
    echo "Could not detect current MCP port from $PLIST_PATH"
    exit 1
fi

reload_needed=true
if [[ "$OLD_PORT" == "$NEW_PORT" ]]; then
    echo "MCP port is already set to $NEW_PORT; verifying health and refreshing client configs"
    reload_needed=false
fi

if [[ "$reload_needed" == true ]]; then
    echo "Updating MCP port: $OLD_PORT -> $NEW_PORT"
    rewrite_plist_port "$PLIST_PATH" "$NEW_PORT"

    # Reload launchd job so the new port takes effect.
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || launchctl unload "$PLIST_PATH" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH" 2>/dev/null || launchctl load "$PLIST_PATH"
    launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true
fi

# Keep future installer runs aligned with the selected MCP port.
rewrite_installer_ports "$NEW_PORT" "$OLD_PORT"

is_mcp_up() {
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${NEW_PORT}/sse" || true)"
    if [[ "$code" != "000" ]]; then
        return 0
    fi
    lsof -n -iTCP:"$NEW_PORT" -sTCP:LISTEN >/dev/null 2>&1
}

# Wait for MCP on new port.
# Startup can take a bit (imports, image preflight), so allow up to 30s.
for _ in $(seq 1 60); do
    if is_mcp_up; then
        break
    fi
    sleep 0.5
done

if is_mcp_up; then
    echo "MCP SSE is up on http://127.0.0.1:${NEW_PORT}/sse"
else
    echo "MCP SSE did not come up on port ${NEW_PORT}."
    echo "Check logs:"
    echo "  ${REPO_DIR}/logs/mcp_sse.log"
    echo "  ${REPO_DIR}/logs/mcp_crash.log"
    exit 1
fi

# Update Claude MCP registration if CLI exists.
if command -v claude >/dev/null 2>&1; then
    claude mcp remove --scope user pentest-agent >/dev/null 2>&1 || true
    claude mcp add --scope user --transport sse pentest-agent "http://127.0.0.1:${NEW_PORT}/sse" >/dev/null
    echo "Updated Claude MCP registration to port ${NEW_PORT}"
else
    echo "claude CLI not found; skipped Claude MCP registration update"
fi

# Update opencode registration if config exists.
if [[ -f "$OPENCODE_CONFIG" ]]; then
    if command -v jq >/dev/null 2>&1; then
        jq --arg url "http://127.0.0.1:${NEW_PORT}/sse" '
            .mcp["pentest-agent"] = ((.mcp["pentest-agent"] // {}) + {
                "type": "remote",
                "url": $url,
                "enabled": true,
                "timeout": 9000000
            })
        ' "$OPENCODE_CONFIG" > "${OPENCODE_CONFIG}.tmp"
        mv "${OPENCODE_CONFIG}.tmp" "$OPENCODE_CONFIG"
        echo "Updated opencode MCP registration to port ${NEW_PORT}"
    else
        echo "jq not found; skipped opencode config update at $OPENCODE_CONFIG"
    fi
fi

echo "Done. New MCP SSE URL: http://127.0.0.1:${NEW_PORT}/sse"
