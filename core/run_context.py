from __future__ import annotations

import os
import re

from core import paths as _paths

_DEFAULT_RUN_ID = "single-run"
_RUN_ID_RE = re.compile(r"[^a-z0-9-]+")


def sanitize_run_id(value: str | None) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    cleaned = _RUN_ID_RE.sub("-", raw).strip("-")
    return cleaned[:48] or _DEFAULT_RUN_ID


def run_id() -> str:
    return sanitize_run_id(os.environ.get("SMITH_RUN_ID"))


def has_explicit_run_id() -> bool:
    return bool(str(os.environ.get("SMITH_RUN_ID") or "").strip())


def multi_run_mode() -> bool:
    if os.environ.get("SMITH_SINGLE_RUN", "").strip().lower() in ("1", "true", "yes"):
        return False
    return has_explicit_run_id()


def workdir() -> str:
    return str(_paths.RUNTIME_ROOT)


def docker_network_name() -> str:
    return f"smith-run-{run_id()}"


def container_name(tool: str) -> str:
    safe_tool = sanitize_run_id(tool)
    return f"smith-{safe_tool}-{run_id()}"
