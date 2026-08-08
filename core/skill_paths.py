"""
Resolve skill directories by NAME, tolerant of domain nesting.

Skills live at ``skills/<name>/`` (flat) OR ``skills/<domain>/<name>/`` (one level
of domain nesting, e.g. ``skills/mobile/android-security/``). Any code that reads
a skill's files at runtime must resolve by NAME through here — never hardcode a
``skills/<name>/...`` path — so moving a skill into a domain folder can't silently
break the read. (core/capabilities.py keeps its own patchable copy of this lookup
for test isolation; keep the two in sync.)
"""
from __future__ import annotations

from pathlib import Path

from core import paths as _paths

SKILLS_DIR = _paths.REPO_ROOT / "skills"


def resolve_skill_dir(name: str) -> Path | None:
    """Return a skill's directory (flat, then one level of domain nesting), or None."""
    if not name:
        return None
    direct = SKILLS_DIR / name
    if direct.is_dir():
        return direct
    try:
        for sub in SKILLS_DIR.iterdir():
            if sub.is_dir():
                cand = sub / name
                if cand.is_dir():
                    return cand
    except OSError:
        pass
    return None


def skill_file(name: str, *parts: str) -> Path | None:
    """Path to a file inside a skill, resolving the dir by name.

    e.g. ``skill_file("ai-redteam", "refs", "role-confusion-payloads.json")``.
    Returns None if the skill dir can't be found."""
    d = resolve_skill_dir(name)
    return d.joinpath(*parts) if d else None
