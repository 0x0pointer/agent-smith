from __future__ import annotations

import os
import shutil
from pathlib import Path


_DOCKER_CANDIDATES = (
    "/usr/bin/docker",
    "/usr/local/bin/docker",
    "/snap/bin/docker",
    "/opt/homebrew/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
)


def docker_executable() -> str:
    """Resolve Docker even when GUI-launched clients provide a minimal PATH."""
    env_path = os.environ.get("DOCKER_BIN")
    if env_path and _is_executable(env_path):
        return env_path

    path_hit = shutil.which("docker")
    if path_hit:
        return path_hit

    for candidate in _DOCKER_CANDIDATES:
        if _is_executable(candidate):
            return candidate

    return "docker"


def _is_executable(path: str) -> bool:
    candidate = Path(path).expanduser()
    return candidate.is_file() and os.access(candidate, os.X_OK)
