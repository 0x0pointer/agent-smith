"""Local Source instance registry helpers."""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

from core.paths import REPO_ROOT

SOURCE_REGISTRY_FILE = REPO_ROOT / "sources.yaml"

_INLINE_URL_RE = re.compile(r"url\s*:\s*([^,}]+)")


def _registry_path(registry_path: str | os.PathLike[str] | None = None) -> Path:
    raw = registry_path or os.environ.get("SOURCE_REGISTRY") or SOURCE_REGISTRY_FILE
    return Path(raw)


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()


def _validate_source_url(url: str) -> str | None:
    raw = str(url or "").strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").strip().lower()
        _ = parsed.port
    except ValueError:
        return None
    if parsed.scheme != "http" or not host:
        return None
    if parsed.username or parsed.password:
        return None
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return None
    netloc = parsed.netloc.rstrip("/")
    path = parsed.path.rstrip("/")
    return f"http://{netloc}{path}"


def _iter_entries(text: str) -> list[tuple[int, str]]:
    entries: list[tuple[int, str]] = []
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        entries.append((lineno, line))
    return entries


def _load_registry(registry_path: str | os.PathLike[str] | None = None) -> dict:
    path = _registry_path(registry_path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"sources": {}, "errors": [f"registry not found: {path}"]}
    except OSError as exc:
        return {"sources": {}, "errors": [f"registry unreadable: {exc}"]}

    entries = _iter_entries(text)
    if not entries:
        return {"sources": {}, "errors": []}

    sources: dict[str, dict[str, str]] = {}
    errors: list[str] = []

    top_level_sources = next(
        (
            len(line) - len(line.lstrip(" "))
            for _, line in entries
            if line.lstrip(" ").startswith("sources:")
            and (len(line) - len(line.lstrip(" "))) == 0
        ),
        None,
    )
    in_sources = top_level_sources is not None
    entry_indent = 2 if in_sources else 0
    i = 0
    while i < len(entries):
        lineno, line = entries[i]
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if in_sources:
            if indent == 0 and stripped == "sources:":
                i += 1
                continue
            if indent < entry_indent:
                i += 1
                continue
            if indent != entry_indent:
                i += 1
                continue
        elif indent != 0:
            i += 1
            continue
        if ":" not in stripped:
            i += 1
            continue
        name, rest = stripped.split(":", 1)
        name = name.strip()
        rest = rest.strip()
        if not name or name == "sources":
            i += 1
            continue

        url = None
        if rest.startswith("{") and rest.endswith("}"):
            match = _INLINE_URL_RE.search(rest[1:-1])
            if match:
                url = match.group(1).strip().strip("'\"")
        elif rest:
            url = rest.strip().strip("'\"")
        else:
            j = i + 1
            while j < len(entries):
                _, child = entries[j]
                child_indent = len(child) - len(child.lstrip(" "))
                if child_indent <= indent:
                    break
                child_stripped = child.strip()
                if child_stripped.startswith("url:"):
                    url = child_stripped.split(":", 1)[1].strip().strip("'\"")
                    break
                j += 1

        valid_url = _validate_source_url(url or "")
        if valid_url:
            sources[name] = {"name": name, "url": valid_url}
        elif url is not None:
            errors.append(f"{name}: invalid url")
        i += 1

    return {"sources": sources, "errors": errors}


def list_sources(registry_path: str | os.PathLike[str] | None = None) -> dict[str, dict[str, str]]:
    """Return the valid Source instances from the configured registry."""
    return _load_registry(registry_path)["sources"]


def resolve_source(name: str, registry_path: str | os.PathLike[str] | None = None) -> dict:
    """Resolve a named Source instance with fail-soft metadata for UI messages."""
    loaded = _load_registry(registry_path)
    sources = loaded["sources"]
    available = sorted(sources)
    wanted = str(name or "").strip()
    if not wanted:
        return {
            "source": None,
            "available": available,
            "error": "No Source was bound to this engagement.",
            "errors": loaded["errors"],
        }
    source = sources.get(wanted)
    if source:
        return {"source": source, "available": available, "error": None, "errors": loaded["errors"]}
    return {
        "source": None,
        "available": available,
        "error": f"Source '{wanted}' is not available.",
        "errors": loaded["errors"],
    }
