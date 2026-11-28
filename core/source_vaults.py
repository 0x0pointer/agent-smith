"""Create and start notes vaults from the platform.

A vault is a folder of Markdown notes served by its own Source instance
(https://github.com/0x0pointer/Source). The Knowledge page could only read vaults
someone had set up by hand: make a folder, build its index, run the service on a
free port, add it to ``sources.yaml``. This module does those steps.

Source itself is used as installed and never modified: its ``build_index.py`` and
``serve_http.py`` are run with fixed arguments. Vault names are short slugs, the
folder is always inside the vaults folder, and nothing goes through a shell.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from core import paths as _paths
from core import sources as _sources

_LOG = logging.getLogger(__name__)

_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_PORTS = range(7801, 7900)
_BUILD_TIMEOUT_S = 900
_START_WAIT_S = 45.0
# Characters the one-line registry entry cannot hold inside a path.
_UNSAFE_PATH_CHARS = set(',{}#"\'\n\r')

_WELCOME_NOTE = """---
tags: [welcome]
---
# {name}

This vault was created from the Agent-Smith platform.

Add Markdown notes to this folder: how you test, what you found, things worth
remembering about a target. Smith looks things up here during a scan that is
bound to this vault, and saves what it learns back to it.
"""


class VaultError(Exception):
    """A vault could not be created or started; ``public`` is safe to show."""

    def __init__(self, public: str, status: int = 400):
        super().__init__(public)
        self.public = public
        self.status = status


# ── Where things are ─────────────────────────────────────────────────────────

def source_dir() -> Path | None:
    """The folder Source is installed in: ``SMITH_SOURCE_DIR``, else a sibling
    ``Source`` checkout next to this repo. None when it is not there."""
    configured = os.environ.get("SMITH_SOURCE_DIR", "").strip()
    candidates = [Path(configured).expanduser()] if configured else [
        _paths.REPO_ROOT.parent / "Source", _paths.REPO_ROOT.parent / "source"]
    for candidate in candidates:
        if (candidate / "serve_http.py").is_file() and (candidate / "build_index.py").is_file():
            return candidate
    return None


def _source_python(folder: Path) -> str:
    """Source's own interpreter when it has a virtualenv (its dependencies live there)."""
    for candidate in (folder / ".venv" / "Scripts" / "python.exe", folder / ".venv" / "bin" / "python"):
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def vaults_dir() -> Path:
    """Where new vaults are created: ``SMITH_VAULTS_DIR``, else ``~/smith-vaults``."""
    configured = os.environ.get("SMITH_VAULTS_DIR", "").strip()
    return Path(configured).expanduser() if configured else Path.home() / "smith-vaults"


def can_create() -> bool:
    return source_dir() is not None


def startable() -> set[str]:
    """Names of the registered vaults the platform knows how to start."""
    if source_dir() is None:
        return set()
    return set(_sources.list_launchable())


# ── Health and ports ─────────────────────────────────────────────────────────

def _healthy(url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/health", timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.3)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def _free_port() -> int:
    taken = set()
    for meta in _sources.list_sources().values():
        try:
            taken.add(urlparse(meta.get("url", "")).port)
        except ValueError:
            continue
    for port in _PORTS:
        if port not in taken and not _port_in_use(port):
            return port
    raise VaultError("No free port was found for a new vault (7801 to 7899 are all in use).", 409)


# ── Registry ─────────────────────────────────────────────────────────────────

def _as_registry_path(path: Path) -> str:
    text = str(path).replace("\\", "/")
    if _UNSAFE_PATH_CHARS & set(text):
        raise VaultError("The vaults folder has a character in its path that the registry cannot hold. "
                         "Set SMITH_VAULTS_DIR to a simpler folder.")
    return text


def _register(name: str, url: str, vault: Path, db: Path) -> None:
    """Add the vault to the registry file, inside its ``sources:`` block."""
    registry = _sources._registry_path()
    entry = f'  {name}: {{url: "{url}", vault: "{_as_registry_path(vault)}", db: "{_as_registry_path(db)}"}}'
    try:
        lines = registry.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    head = next((i for i, line in enumerate(lines) if line.strip() == "sources:" and not line.startswith(" ")), None)
    if head is None:
        lines += ["sources:", entry]
    else:
        end = head + 1
        for i in range(head + 1, len(lines)):
            stripped = lines[i].strip()
            if stripped and not stripped.startswith("#") and not lines[i].startswith(" "):
                break                               # the next top-level key
            if stripped:
                end = i + 1
        lines.insert(end, entry)
    registry.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── Running Source ───────────────────────────────────────────────────────────

def _detached() -> dict:
    """Popen options that keep the service running after this request ends."""
    if sys.platform != "win32":
        return {"start_new_session": True}
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    return {"creationflags": flags | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)}


def _build_index(folder: Path, vault: Path, db: Path) -> None:
    db.parent.mkdir(parents=True, exist_ok=True)
    try:
        done = subprocess.run(
            [_source_python(folder), str(folder / "build_index.py"), "--vault", str(vault), "--db", str(db)],
            cwd=str(folder), capture_output=True, text=True, encoding="utf-8", errors="replace",
            stdin=subprocess.DEVNULL, timeout=_BUILD_TIMEOUT_S, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VaultError("Building the vault's search index took too long.", 504) from exc
    except OSError as exc:
        _LOG.warning("vault index build could not start: %s", exc)
        raise VaultError("Source could not be run. Check that it is installed.", 502) from exc
    if done.returncode != 0:
        _LOG.warning("vault index build failed (%s): %s", done.returncode, (done.stderr or "")[-2000:])
        raise VaultError("Source could not build the search index for this vault. "
                         "The reason is in the platform log.", 502)


def _launch(folder: Path, name: str, vault: Path, db: Path, port: int) -> int:
    logs = _paths.LOGS_DIR
    logs.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["INSTANCE"] = name
    try:
        with (logs / f"source-{name}.log").open("a", encoding="utf-8") as log:
            proc = subprocess.Popen(
                [_source_python(folder), str(folder / "serve_http.py"),
                 "--vault", str(vault), "--db", str(db), "--port", str(port)],
                cwd=str(folder), env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, **_detached(),
            )
    except OSError as exc:
        _LOG.warning("vault %s could not be started: %s", name, exc)
        raise VaultError("Source could not be run. Check that it is installed.", 502) from exc
    (logs / f"source-{name}.pid").write_text(str(proc.pid), encoding="utf-8")
    return int(proc.pid)


def _wait_until_up(url: str, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _healthy(url):
            return True
        time.sleep(0.5)
    return _healthy(url)


def _require_source() -> Path:
    folder = source_dir()
    if folder is None:
        raise VaultError("Source is not installed on this computer. Install it next to the agent-smith "
                         "folder, or set SMITH_SOURCE_DIR to where it is.", 409)
    return folder


# ── What the platform calls ──────────────────────────────────────────────────

def start_vault(name: str) -> dict:
    """Start the Source for a registered vault. A vault already answering is left alone."""
    folder = _require_source()
    entry = _sources.list_launchable().get(name)
    if not entry:
        raise VaultError("The platform does not know where this vault's folder is, so it cannot start it. "
                         "Add vault: \"<folder>\" to its line in sources.yaml.", 409)
    url = entry["url"]
    if _healthy(url):
        return {"name": name, "url": url, "status": "running"}
    vault = Path(entry["vault"]).expanduser()
    if not vault.is_dir():
        raise VaultError("This vault's folder no longer exists.", 409)
    db = Path(entry["db"]).expanduser() if entry.get("db") else vault.parent / ".index" / f"{name}.sqlite"
    port = urlparse(url).port
    if not port:
        raise VaultError("This vault's address in sources.yaml has no port.", 409)
    if _port_in_use(port):
        raise VaultError(f"Port {port} is in use by something that is not this vault.", 409)
    if not db.is_file():
        _build_index(folder, vault, db)
    _launch(folder, name, vault, db, port)
    up = _wait_until_up(url, _START_WAIT_S)
    return {"name": name, "url": url, "status": "running" if up else "starting"}


def create_vault(name: object) -> dict:
    """Make a new vault: folder, first note, index, a running Source, a registry entry."""
    folder = _require_source()
    name = str(name or "").strip().lower()
    if not _NAME_RE.match(name):
        raise VaultError("Use 1 to 32 lowercase letters, digits or hyphens for the name, "
                         "starting and ending with a letter or digit.")
    if name in _sources.list_sources():
        raise VaultError("A vault with that name already exists.", 409)
    root = vaults_dir()
    vault, db = root / name, root / ".index" / f"{name}.sqlite"
    if vault.exists() and any(vault.iterdir()):
        raise VaultError("A folder with that name already exists in the vaults folder and is not empty.", 409)
    _as_registry_path(vault)                         # refuse before anything is created
    port = _free_port()
    url = f"http://127.0.0.1:{port}"

    vault.mkdir(parents=True, exist_ok=True)
    note = vault / "welcome.md"
    note.write_text(_WELCOME_NOTE.format(name=name), encoding="utf-8")
    try:
        _build_index(folder, vault, db)
    except VaultError:
        # Leave nothing half-made behind, so the same name can be tried again.
        note.unlink(missing_ok=True)
        try:
            vault.rmdir()
        except OSError:
            pass
        raise
    _register(name, url, vault, db)
    _launch(folder, name, vault, db, port)
    up = _wait_until_up(url, _START_WAIT_S)
    return {"name": name, "url": url, "folder": str(vault), "status": "running" if up else "starting"}
