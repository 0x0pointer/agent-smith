#!/usr/bin/env bash
# post-compact.sh — SessionStart(compact) hook
# Reads session.json after context compaction and injects a brief
# recovery reminder so Claude re-invokes the active skill.
# Exits silently when no session is running (no noise outside pentests).

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SESSION_FILE="$REPO_DIR/session.json"

[[ ! -f "$SESSION_FILE" ]] && exit 0

python3 - "$SESSION_FILE" <<'PYEOF'
import json, sys

try:
    data = json.loads(open(sys.argv[1]).read())
except Exception:
    sys.exit(0)

if data.get("status") != "running":
    sys.exit(0)

skill = data.get("skill", "")
target = data.get("target", "")
depth = data.get("depth", "")
step = data.get("current_step", "")
tools = data.get("tools_called", [])

print("CONTEXT RECOVERY AFTER COMPACTION")
print(f"Active scan: {target} (depth={depth})")
if tools:
    print(f"Tools already run: {', '.join(tools)}")
if step:
    print(f"Resume at step: {step}")
if skill:
    print(f"Active skill: /{skill}")
    print(f"ACTION REQUIRED: Re-invoke the /{skill} skill to reload its workflow.")
    print(f"Then call session(action='status') to see what tools have already run.")
else:
    print("Call session(action='status') to recover scan context.")
PYEOF
