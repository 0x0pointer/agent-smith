# Extending agent-smith

---

## Architecture: the dispatch pattern

agent-smith uses **5 MCP tools** that each dispatch to many underlying actions:

| MCP tool | Dispatches via | Registered in |
|----------|---------------|---------------|
| `scan()` | `tool=` param (nmap, nuclei, ffuf, ...) | `mcp_server/scan_tools.py` |
| `kali()` | freeform shell command | `mcp_server/kali_tools.py` |
| `http()` | `action=` param (request, save_poc) | `mcp_server/http_tools.py` |
| `report()` | `action=` param (finding, diagram, note, dashboard) | `mcp_server/report_tools.py` |
| `session()` | `action=` param (start, complete, status, ...) | `mcp_server/session_tools.py` |

**Do NOT add new top-level MCP tools.** Always add new capabilities as a dispatch value inside an existing tool. This keeps the system prompt small and prevents context bloat as the toolset grows.

Why this matters:
- MCP tool schemas are sent in every API call — more tools = more tokens consumed before the LLM even starts thinking
- CLAUDE.md documents how to use each tool — more tools = larger system prompt
- The dispatch pattern scales: 5 tools can cover 50+ scanners without growing the schema

---

## Adding a new lightweight Docker scanner

New scanners go through `scan(tool="X")`. Three files to touch:

### 1. Create the tool definition

Create `tools/mytool.py`:

```python
from tools.base import Tool

def _parse(stdout: str, stderr: str) -> list[dict]:
    """Optional: parse raw output into structured findings."""
    return None  # return None to pass raw stdout through

mytool = Tool(
    name         = "mytool",
    image        = "docker.io/vendor/mytool:latest",
    build_args   = lambda **kw: [
        "--flag", kw["target"],
        *(kw["flags"].split() if kw.get("flags") else []),
    ],
    parser        = _parse,
    needs_mount   = False,           # True if scanning a local codebase
    forward_env   = ["MY_API_KEY"],  # env vars to pass into the container
    extra_volumes = None,
    default_timeout = 120,
    max_output    = 10_000,
)
```

### 2. Register it in the registry

Add to `tools/__init__.py`:

```python
from tools.mytool import mytool

REGISTRY: dict[str, Tool] = {
    ...
    "mytool": mytool,
}
```

### 3. Add the dispatch entry in scan_tools.py

In `mcp_server/scan_tools.py`, add `"mytool"` to the dispatch logic inside the `scan()` function. It will automatically use `_run("mytool", ...)` — no new `@mcp.tool()` decorator needed.

### 4. Document it

Add one row to the `scan()` table in `CLAUDE.md`:

```markdown
| mytool | host/IP | option1=default |
```

That's it. No new MCP tool, no new schema, no system prompt growth.

---

## Adding a Kali-based tool

Tools that need the full Kali environment run via `kali(command="...")`. No code changes needed — just install the tool in the image.

### 1. Install in the Kali image

Add to `tools/kali/Dockerfile`:

```dockerfile
RUN apt-get install -y mytool \
    || pip3 install mytool
```

Rebuild:
```bash
docker build -t pentest-agent/kali-mcp ./tools/kali/
```

### 2. Use it

```
kali(command="mytool --target example.com")
```

No registration needed. Document it in `CLAUDE.md` under the Kali deep-dive examples if it's commonly used.

---

## Adding a new skill

Skills are on-demand instruction sets — loaded only when invoked, so they don't bloat the system prompt.

### 1. Create the skill file

```
skills/my-skill/SKILL.md
```

```markdown
---
name: my-skill
description: What this skill does in one line
---

# My Skill

You are doing X. Follow these steps:

1. ...
2. ...
3. Call `report_finding` for every confirmed vulnerability.
```

### 2. Install it

Add to `installers/install.sh`:

```bash
cp "$REPO_DIR/skills/my-skill/SKILL.md" "$HOME/.claude/skills/my-skill.md"
```

Add the reverse to `installers/uninstall.sh`:

```bash
rm -f "$HOME/.claude/skills/my-skill.md"
```

### 3. Document it

Add one row to the skills table in `CLAUDE.md`.

**Put detailed usage docs in the skill file, not in CLAUDE.md.** CLAUDE.md should only have a one-line trigger description per skill.

---

## Adding a new action to an existing dispatcher

If your feature isn't a scanner but fits an existing tool (e.g. a new report format), add it as an action:

1. Add the handler in the appropriate `mcp_server/*_tools.py` module
2. Add it to the dispatch `if/elif` chain in the tool function
3. Add one row to the tool's table in `CLAUDE.md`

---

## Project conventions

- **MCP tools are thin wrappers.** Logic belongs in `core/` or `tools/`, not in `mcp_server/`.
- **All tool calls** must call `log.tool_call()` before and `log.tool_result()` after.
- **All tool calls** that consume tokens must call `cost_tracker.start()` / `cost_tracker.finish()`.
- **Scan limits** must be checked via `scan_session.check_limits()` before any active tool call.
- **`report_finding`** is the only way to log vulnerabilities.
- **Keep CLAUDE.md lean** — one-line-per-tool tables, no multi-line descriptions. Detailed docs go in skill files or this extending guide.
