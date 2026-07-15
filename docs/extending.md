# Extending agent-smith

---

## Architecture: the dispatch pattern

agent-smith uses **5 MCP tools** that each dispatch to many underlying actions:

| MCP tool | Dispatches via | Registered in |
|----------|---------------|---------------|
| `scan()` | `tool=` param (nmap, nuclei, ffuf, ...) | `mcp_server/scan_tools/` (package) |
| `kali()` | freeform shell command | `mcp_server/kali_tools.py` |
| `http()` | `action=` param (request, save_poc) | `mcp_server/http_tools.py` |
| `report()` | `action=` param (finding, diagram, note, dashboard) | `mcp_server/report_tools/` (package) |
| `session()` | `action=` param (start, complete, status, ...) | `mcp_server/session_tools/` (package) |

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

def _build_args(target: str, flags: str = "") -> list[str]:
    """Build the container argv from the scan() call's params."""
    return ["--flag", target, *(flags.split() if flags else [])]

def _parse(stdout: str, stderr: str) -> list[dict]:
    """Optional: parse raw output into structured findings."""
    return None  # return None to pass raw stdout through

# The module-level variable MUST be named TOOL — the registry imports it by that name.
TOOL = Tool(
    name         = "mytool",
    image        = "docker.io/vendor/mytool:latest",
    build_args   = _build_args,
    parser        = _parse,
    needs_mount   = False,           # True if scanning a local codebase
    forward_env   = ["MY_API_KEY"],  # env vars to pass into the container
    default_timeout = 120,
    max_output    = 10_000,
)
```

### 2. Register it in the registry

Add to `tools/__init__.py` — import `TOOL` under a private alias and key the entry by `.name`:

```python
from tools.mytool import TOOL as _mytool

REGISTRY = {
    ...
    _mytool.name: _mytool,
}
```

### 3. Add the dispatch entry in the scan_tools package

`mcp_server/scan_tools/` is a package: add `"mytool"` to the dispatch logic in the relevant `handlers_*.py` (e.g. `handlers_net.py` for a network scanner, `handlers_code.py` for a static-analysis tool, `handlers_ai.py` / `handlers_mobile.py` / `handlers_exploit.py` for their domains). It will automatically use `_run("mytool", ...)` — no new `@mcp.tool()` decorator needed.

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

Skills live in a separate repo ([github.com/0x0pointer/skills](https://github.com/0x0pointer/skills)) pulled in as a git submodule at `skills/`.

### 1. Create the skill file

Clone the skills repo and add your skill under `skills/<domain>/<name>/SKILL.md` (one level of
domain nesting, e.g. `skills/mobile/android-security/`):

```
skills/<domain>/my-skill/SKILL.md
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

Commit and push to the skills repo, then update the submodule pointer in agent-smith:

```bash
cd skills && git pull origin main && cd ..
git add skills
git commit -m "update skills submodule"
```

### 2. Re-run the installer — skills are auto-discovered

No manual `install.sh` / `uninstall.sh` edits are needed. `installers/install.sh` discovers every
skill automatically with:

```bash
find "$REPO_DIR/skills" -mindepth 2 -maxdepth 3 -name SKILL.md
```

So just add the skill at `skills/<domain>/<name>/SKILL.md` and re-run `./installers/install.sh`; it
installs the new skill (and `uninstall.sh` removes whatever was installed). No per-skill `mkdir`/`cp`.

### 3. Document it

Add one row to the skills table in `CLAUDE.md`.

**Put detailed usage docs in the skill file, not in CLAUDE.md.** CLAUDE.md should only have a one-line trigger description per skill.

---

## Adding a new action to an existing dispatcher

If your feature isn't a scanner but fits an existing tool (e.g. a new report format), add it as an action:

1. Add the handler in the appropriate tool module — `mcp_server/http_tools.py` / `kali_tools.py`, or the
   relevant submodule of the `mcp_server/report_tools/` and `mcp_server/session_tools/` packages
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
