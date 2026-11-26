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
    return f"{parsed.scheme}://{netloc}{path}"


def _iter_entries(text: str) -> list[tuple[int, str]]:
    entries: list[tuple[int, str]] = []
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        entries.append((lineno, line))
    return entries


def _sources_block_indent(entries: list[tuple[int, str]]) -> int | None:
    for _, line in entries:
        indent = len(line) - len(line.lstrip(" "))
        if line.lstrip(" ").startswith("sources:") and indent == 0:
            return indent
    return None


def _entry_in_scope(in_sources: bool, entry_indent: int, indent: int, stripped: str) -> bool:
    if not in_sources:
        return indent == 0
    if indent < entry_indent or indent != entry_indent:
        return False
    return stripped != "sources:"


def _entry_name_and_rest(stripped: str) -> tuple[str, str] | None:
    if ":" not in stripped:
        return None
    name, rest = stripped.split(":", 1)
    name = name.strip()
    if not name or name == "sources":
        return None
    return name, rest.strip()


def _inline_or_scalar_url(rest: str) -> str | None:
    if rest.startswith("{") and rest.endswith("}"):
        match = _INLINE_URL_RE.search(rest[1:-1])
        return match.group(1).strip().strip("'\"") if match else None
    if rest:
        return rest.strip().strip("'\"")
    return None


def _child_url(entries: list[tuple[int, str]], start: int, parent_indent: int) -> str | None:
    for _, child in entries[start:]:
        child_indent = len(child) - len(child.lstrip(" "))
        if child_indent <= parent_indent:
            return None
        child_stripped = child.strip()
        if child_stripped.startswith("url:"):
            return child_stripped.split(":", 1)[1].strip().strip("'\"")
    return None


def _entry_url(entries: list[tuple[int, str]], index: int, indent: int, rest: str) -> str | None:
    inline = _inline_or_scalar_url(rest)
    if inline is not None:
        return inline
    return _child_url(entries, index + 1, indent)


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

    in_sources = _sources_block_indent(entries) is not None
    entry_indent = 2 if in_sources else 0
    for i, (_, line) in enumerate(entries):
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if not _entry_in_scope(in_sources, entry_indent, indent, stripped):
            continue
        entry = _entry_name_and_rest(stripped)
        if not entry:
            continue
        name, rest = entry
        url = _entry_url(entries, i, indent, rest)
        valid_url = _validate_source_url(url or "")
        if valid_url:
            sources[name] = {"name": name, "url": valid_url}
        elif url is not None:
            errors.append(f"{name}: invalid url")

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
