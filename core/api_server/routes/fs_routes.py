"""Folder picker for the New Scan wizard's "Source code" field.

A white-box scan needs the path of a folder on the machine the platform runs
on. A browser cannot hand a web page that path (its folder dialog only yields
file contents), so the wizard browses folders through this endpoint instead:

* ``GET /api/fs/folders``            — the starting points (home folder, drives)
* ``GET /api/fs/folders?path=<dir>`` — that folder's sub-folders, plus a short
  description of what kind of project it looks like

Operator token only. It lists **folder names only** — never file names or file
contents — and skips hidden and system folders; the ``markers`` it reports come
from a fixed list of well-known project files checked by name.
"""
from __future__ import annotations

import asyncio
import os
import string
import sys

from fastapi import Request
from fastapi.responses import JSONResponse

from ._common import router

_MAX_FOLDERS = 400
_MAX_PATH = 1024
# Well-known files and folders that say what a project is. Checked by name only.
_MARKERS = (
    (".git", "Git repository"),
    ("package.json", "Node.js"),
    ("pyproject.toml", "Python"),
    ("requirements.txt", "Python"),
    ("pom.xml", "Java (Maven)"),
    ("build.gradle", "Java / Kotlin (Gradle)"),
    ("build.gradle.kts", "Java / Kotlin (Gradle)"),
    ("go.mod", "Go"),
    ("Cargo.toml", "Rust"),
    ("composer.json", "PHP"),
    ("Gemfile", "Ruby"),
    ("AndroidManifest.xml", "Android"),
    ("Dockerfile", "Docker"),
)
_SKIP_NAMES = {"$recycle.bin", "system volume information", "node_modules", "__pycache__"}


def _is_operator(request: Request) -> bool:
    return getattr(request.state, "role", "") == "operator"


def _roots() -> list[dict]:
    """Where browsing can start: the home folder, then drives (Windows) or /."""
    home = os.path.expanduser("~")
    roots = [{"name": "Home", "path": home}] if os.path.isdir(home) else []
    if sys.platform == "win32":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.isdir(drive):
                roots.append({"name": drive, "path": drive})
    else:
        roots.append({"name": "/", "path": "/"})
    return roots


def _hidden(entry: os.DirEntry) -> bool:
    name = entry.name
    if name.startswith(".") or name.lower() in _SKIP_NAMES:
        return True
    if sys.platform == "win32":
        try:
            attrs = entry.stat(follow_symlinks=False).st_file_attributes
        except (OSError, AttributeError):
            return False
        return bool(attrs & 0x2) or bool(attrs & 0x4)        # hidden | system
    return False


def describe_folder(raw: str) -> dict | None:
    """Sub-folders and project markers of ``raw``; None when it is not a readable folder."""
    text = str(raw or "").strip().strip('"')
    if not text or len(text) > _MAX_PATH or "\x00" in text:
        return None
    expanded = os.path.expanduser(text)
    if not os.path.isabs(expanded):
        return None
    path = os.path.realpath(expanded)
    if not os.path.isdir(path):
        return None
    folders: list[dict] = []
    files = 0
    names: set[str] = set()
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                names.add(entry.name)
                try:
                    is_dir = entry.is_dir()
                except OSError:
                    continue
                if not is_dir:
                    files += 1
                elif not _hidden(entry) and len(folders) < _MAX_FOLDERS:
                    folders.append({"name": entry.name, "path": os.path.join(path, entry.name)})
    except OSError:
        return None
    folders.sort(key=lambda f: f["name"].lower())
    parent = os.path.dirname(path)
    markers: list[str] = []
    for filename, label in _MARKERS:
        if filename in names and label not in markers:
            markers.append(label)
    return {
        "path": path,
        "parent": parent if parent != path else "",
        "is_root": parent == path,
        "folders": folders,
        "files": files,
        "markers": markers,
    }


@router.get("/api/fs/folders")
async def api_fs_folders(request: Request, path: str = "") -> JSONResponse:
    if not _is_operator(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    roots = await asyncio.to_thread(_roots)
    if not path.strip():
        return JSONResponse({"roots": roots, "path": "", "folders": []})
    described = await asyncio.to_thread(describe_folder, path)
    if described is None:
        return JSONResponse({"error": "That folder was not found on this computer.", "roots": roots},
                            status_code=404)
    return JSONResponse({"roots": roots, **described})
