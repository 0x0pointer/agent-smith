"""
FastAPI web server
==================
Serves the dashboard UI and REST API on the same port (default 5000).

Routes
------
  GET /               → dashboard UI
  GET /api/findings   → current scan findings + diagrams (findings.json)
  GET /api/session    → current scan session state (session.json)
  GET /api/cost       → current scan cost breakdown (session_cost.json)
  GET /api/logs       → current session log lines

Usage
-----
  from core.api_server import serve
  url = await serve(port=5000)
  # → "http://localhost:5000"
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

_log = logging.getLogger(__name__)

_REPO_ROOT         = Path(__file__).parent.parent
_FINDINGS_FILE     = _REPO_ROOT / "findings.json"
_SESSION_FILE      = _REPO_ROOT / "session.json"
_COST_FILE         = _REPO_ROOT / "session_cost.json"
_TEMPLATES_DIR     = _REPO_ROOT / "templates"
_THREAT_MODEL_DIR = _REPO_ROOT / "threat-model"

# ── FastAPI app ───────────────────────────────────────────────────────────────

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="pentest-agent")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def dashboard_ui() -> FileResponse:
    return FileResponse(_TEMPLATES_DIR / "dashboard.html")


@app.get("/api/findings")
async def api_findings() -> JSONResponse:
    return JSONResponse(_read_json(_FINDINGS_FILE))


@app.get("/api/session")
async def api_session() -> JSONResponse:
    return JSONResponse(_read_json(_SESSION_FILE))


@app.get("/api/cost")
async def api_cost() -> JSONResponse:
    return JSONResponse(_read_json(_COST_FILE))


# Cache: (filepath, mtime) -> svgs dict
_svg_cache: dict[str, tuple[float, dict[str, str]]] = {}


def _prerender_mermaid_sync(content: str) -> dict[str, str]:
    """Blocking: extract mermaid blocks and render each to SVG via mmdc."""
    import re, subprocess, tempfile, os
    blocks = re.findall(r'```mermaid\n(.*?)```', content, re.DOTALL)
    svgs: dict[str, str] = {}
    for i, block in enumerate(blocks):
        try:
            # Replace literal \n inside labels with a space
            clean = block.replace('\\n', ' ')
            # Remap light pastel style colors to dark equivalents
            _COLOR_MAP = {
                'fill:#f44': 'fill:#7a0000', 'fill:#f88': 'fill:#6b1a1a',
                'fill:#faa': 'fill:#5c1a1a', 'fill:#fcc': 'fill:#4d1a1a',
                'fill:#ffd': 'fill:#3d3000', 'fill:#ffa': 'fill:#3d3000',
                'fill:#ddf': 'fill:#1a2a4a', 'fill:#bbf': 'fill:#1a2040',
                'stroke:#c00': 'stroke:#ff6666', 'stroke:#a00': 'stroke:#ff5555',
                'stroke:#c44': 'stroke:#ff8888', 'stroke:#aa0': 'stroke:#ddcc00',
                'stroke:#44a': 'stroke:#6699ff',
            }
            for light, dark in _COLOR_MAP.items():
                clean = clean.replace(light, dark)
            with tempfile.NamedTemporaryFile(suffix='.mmd', mode='w', delete=False) as f:
                f.write(clean)
                inp = f.name
            out = inp.replace('.mmd', '.svg')
            subprocess.run(
                ['npx', '@mermaid-js/mermaid-cli', '-i', inp, '-o', out,
                 '-c', str(_REPO_ROOT / 'core' / 'mermaid-config.json'),
                 '--backgroundColor', 'transparent'],
                capture_output=True, text=True, timeout=60,
                cwd=str(_REPO_ROOT),
            )
            if Path(out).exists():
                svgs[str(i)] = Path(out).read_text()
                os.unlink(out)
            os.unlink(inp)
        except Exception:
            pass
    return svgs


async def _get_svgs(candidate: Path, content: str) -> dict[str, str]:
    """Return cached SVGs or render in a thread pool (non-blocking)."""
    import asyncio
    key = str(candidate)
    mtime = candidate.stat().st_mtime
    if key in _svg_cache and _svg_cache[key][0] == mtime:
        return _svg_cache[key][1]
    loop = asyncio.get_event_loop()
    svgs = await loop.run_in_executor(None, _prerender_mermaid_sync, content)
    _svg_cache[key] = (mtime, svgs)
    return svgs


@app.get("/api/threat-model")
async def api_get_threat_model(file: str = "") -> JSONResponse:
    files: list[str] = []
    if _THREAT_MODEL_DIR.exists():
        files = sorted([p.name for p in _THREAT_MODEL_DIR.glob("*.md")], reverse=True)

    if not file and files:
        file = files[0]

    content = ""
    svgs: dict[str, str] = {}
    if file:
        if "/" in file or "\\" in file or ".." in file:
            return JSONResponse({"error": "invalid file"}, status_code=400)
        candidate = (_THREAT_MODEL_DIR / file).resolve()
        if not str(candidate).startswith(str(_THREAT_MODEL_DIR.resolve())):
            return JSONResponse({"error": "invalid file"}, status_code=400)
        if candidate.exists():
            content = candidate.read_text(encoding="utf-8")
            svgs = await _get_svgs(candidate, content)

    return JSONResponse({"files": files, "file": file, "content": content, "svgs": svgs})


@app.patch("/api/findings/{finding_id}")
async def api_patch_finding(finding_id: str, request: Request) -> JSONResponse:
    from core.findings import update_finding
    try:
        body = await request.json()
        gh_issue = body.get("gh_issue", "")
        updated = await update_finding(finding_id, gh_issue)
        return JSONResponse({"ok": updated})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.get("/api/logs")
async def api_logs(file: str = "") -> JSONResponse:
    from core.logger import log_path, _LOG_DIR
    try:
        all_files = sorted(
            [p.name for p in _LOG_DIR.glob("*.log")],
            reverse=True,
        )
        target = _LOG_DIR / file if file else log_path
        if not target.resolve().is_relative_to(_LOG_DIR.resolve()):
            return JSONResponse({"lines": [], "files": all_files, "error": "invalid path"})
        lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        return JSONResponse({"lines": lines, "file": target.name, "files": all_files})
    except Exception as exc:
        return JSONResponse({"lines": [], "files": [], "error": str(exc)})


# ── Server lifecycle ──────────────────────────────────────────────────────────

_PID_FILE = _REPO_ROOT / "logs" / "dashboard.pid"


def _read_pid() -> int | None:
    try:
        return int(_PID_FILE.read_text().strip())
    except Exception:
        return None


def _write_pid(pid: int) -> None:
    _PID_FILE.write_text(str(pid))


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _port_healthy(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


async def serve(port: int = 5000) -> str:
    """
    Start the dashboard server as an independent background process.
    Survives MCP server restarts — uses a PID file to detect and reuse
    a previously spawned dashboard instead of killing it.
    """
    import signal
    import subprocess as _sp

    # Check PID file first — survives MCP server restarts
    saved_pid = _read_pid()
    if saved_pid and _pid_alive(saved_pid) and _port_healthy(port):
        return f"http://localhost:{port}"

    # Old process died or never existed — clean up stale PID on port
    if saved_pid and _pid_alive(saved_pid):
        try:
            os.kill(saved_pid, signal.SIGTERM)
            await asyncio.sleep(0.3)
        except OSError:
            pass

    # Fire-and-forget: Popen returns immediately, child runs independently.
    # stdout/stderr → /dev/null so the MCP stdio pipe is never touched.
    # start_new_session=True detaches from MCP server's process group.
    proc = _sp.Popen(
        [sys.executable, "-m", "uvicorn",
         "core.api_server:app",
         "--host", "0.0.0.0",
         "--port", str(port),
         "--no-access-log",
         "--log-level", "critical"],
        stdout=_sp.DEVNULL,
        stderr=_sp.DEVNULL,
        cwd=str(_REPO_ROOT),
        start_new_session=True,
    )
    _write_pid(proc.pid)

    await asyncio.sleep(1.5)     # give uvicorn time to bind the port
    return f"http://localhost:{port}"
