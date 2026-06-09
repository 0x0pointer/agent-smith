#!/usr/bin/env bash
# Stable launcher for the pentest-agent MCP server.
#
# Codex Desktop and shell sessions do not always inherit the same PATH.  Do not
# rely on a bare "poetry" command in MCP config; resolve Poetry here, resolve the
# project virtualenv, cd into the checkout, then exec the server.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

_find_poetry() {
    if command -v poetry >/dev/null 2>&1; then
        command -v poetry
        return 0
    fi

    local macos_poetry="$HOME/Library/Application Support/pypoetry/venv/bin/poetry"
    if [[ -x "$macos_poetry" ]]; then
        printf '%s\n' "$macos_poetry"
        return 0
    fi

    local local_poetry="$HOME/.local/bin/poetry"
    if [[ -x "$local_poetry" ]]; then
        printf '%s\n' "$local_poetry"
        return 0
    fi

    return 1
}

_resolve_venv_python() {
    local poetry_bin="$1"
    local executable=""
    local env_path=""

    executable="$("$poetry_bin" -C "$REPO_DIR" env info --executable 2>/dev/null || true)"
    if [[ -n "$executable" && -x "$executable" ]]; then
        printf '%s\n' "$executable"
        return 0
    fi

    env_path="$("$poetry_bin" -C "$REPO_DIR" env list --full-path 2>/dev/null | awk '
        index($0, "(Activated)") { print $1; found = 1; exit }
        NR == 1 { first = $1 }
        END { if (!found && first) print first }
    ')"
    executable="${env_path%/}/bin/python"
    if [[ -n "$env_path" && -x "$executable" ]]; then
        printf '%s\n' "$executable"
        return 0
    fi

    return 1
}

POETRY_BIN="$(_find_poetry)" || {
    echo "Could not find Poetry. Install it or add it to PATH." >&2
    exit 1
}

VENV_PYTHON="$(_resolve_venv_python "$POETRY_BIN")" || {
    echo "Could not determine the pentest-agent virtualenv Python." >&2
    echo "Run: \"$POETRY_BIN\" -C \"$REPO_DIR\" install --no-interaction" >&2
    exit 1
}

case "${1:-}" in
    --print-python)
        printf '%s\n' "$VENV_PYTHON"
        exit 0
        ;;
    --self-test)
        cd "$REPO_DIR"
        PYTHONPATH="$REPO_DIR" "$VENV_PYTHON" - <<'PY'
import importlib

for module in (
    "mcp_server.scan_tools",
    "mcp_server.kali_tools",
    "mcp_server.http_tools",
    "mcp_server.report_tools",
    "mcp_server.session_tools",
):
    importlib.import_module(module)

from mcp_server._app import mcp

expected = {"scan", "kali", "http", "report", "session"}
actual = {tool.name for tool in mcp._tool_manager.list_tools()}
missing = sorted(expected - actual)
extra = sorted(actual - expected)
if missing or extra:
    raise SystemExit(f"MCP tool registration mismatch. missing={missing} extra={extra}")

print("MCP self-test OK: " + ", ".join(sorted(actual)))
PY
        exit 0
        ;;
esac

cd "$REPO_DIR"
exec env PYTHONPATH="$REPO_DIR" "$VENV_PYTHON" -m mcp_server "$@"
