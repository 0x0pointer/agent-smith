# Extending agent-smith

---

## Adding a new lightweight Docker tool

Lightweight tools run as ephemeral `docker run --rm` containers. They are defined in `tools/` and auto-registered via the `REGISTRY` dict.

### 1. Create the tool definition

Create `tools/mytool.py` following the pattern of any existing tool:

```python
# tools/mytool.py
from tools.base import Tool

def _parse(stdout: str, stderr: str) -> list[dict]:
    """Optional: parse raw output into structured findings."""
    # Return None to skip structured parsing and return raw stdout
    return None

mytool = Tool(
    name         = "mytool",
    image        = "docker.io/vendor/mytool:latest",
    build_args   = lambda **kw: [
        "--flag", kw["target"],
        *(kw["flags"].split() if kw.get("flags") else []),
    ],
    parser        = _parse,          # or None for raw output
    needs_mount   = False,           # True if scanning a local codebase
    forward_env   = ["MY_API_KEY"],  # env vars to pass into the container
    extra_volumes = None,            # extra docker volume mounts
    default_timeout = 120,
    max_output    = 10_000,
)
```

### 2. Register it

Add to `tools/__init__.py`:

```python
from tools.mytool import mytool

REGISTRY: dict[str, Tool] = {
    ...
    "mytool": mytool,
}
```

### 3. Add the MCP tool wrapper

Add to the appropriate module in `mcp_server/` (e.g. `mcp_server/web.py` for a web scanner):

```python
@mcp.tool()
async def run_mytool(target: str, flags: str = "") -> str:
    """One-line description. Args: target, flags."""
    return await _run("mytool", target=target, flags=flags)
```

That's it. The tool is now available to Claude on the next MCP server start.

---

## Adding a Kali-based tool

Tools that need the full Kali environment (e.g. they depend on system libraries, Ruby gems, or are not on Docker Hub) run via `kali_exec`.

### 1. Install the tool in the Kali image

Add an install step to `tools/kali/Dockerfile`:

```dockerfile
RUN apt-get install -y mytool \
    || pip3 install mytool
```

Rebuild the image:
```bash
docker build -t pentest-agent/kali-mcp ./tools/kali/
```

### 2. Add the MCP tool wrapper

```python
# mcp_server/web.py (or appropriate module)
@mcp.tool()
async def run_mytool(target: str, flags: str = "") -> str:
    """One-line description."""
    from tools import kali_runner

    stop = scan_session.check_limits(cost_tracker.get_summary())
    if stop:
        return stop

    cmd = f"mytool --target {shlex.quote(target)}"
    if flags:
        cmd += f" {shlex.join(shlex.split(flags))}"

    log.tool_call("mytool", {"target": target})
    call_id = cost_tracker.start("mytool")
    result  = _clip(await kali_runner.exec_command(cmd, timeout=120), 10_000)
    cost_tracker.finish(call_id, result)
    log.tool_result("mytool", result)
    return result
```

---

## Adding a new skill

Skills are Markdown files with YAML frontmatter that Claude reads as instructions.

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

Add a line to `installers/install.sh`:

```bash
cp "$REPO_DIR/skills/my-skill/SKILL.md" "$HOME/.claude/skills/my-skill.md"
```

Add the reverse to `installers/uninstall.sh`:

```bash
rm -f "$HOME/.claude/skills/my-skill.md"
```

### 3. Document when to use it

Add an entry to the skills table in `CLAUDE.md`:

```markdown
| `/my-skill` | User asks to do X | Does Y with Z tools |
```

## Project conventions

- **MCP tools** are thin wrappers. Logic belongs in `core/` or `tools/`, not in `mcp_server/`.
- **All tool calls** must call `log.tool_call()` before and `log.tool_result()` after.
- **All tool calls** that consume tokens must call `cost_tracker.start()` / `cost_tracker.finish()`.
- **Scan limits** must be checked via `scan_session.check_limits()` before any active tool call.
- **`report_finding`** is the only way to log vulnerabilities — it handles both JSON and Neo4j writes.
