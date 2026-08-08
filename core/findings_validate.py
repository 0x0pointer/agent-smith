"""
Deterministic finding-trace validator
======================================
Zero-LLM, zero-dependency structural + filesystem validation of a finding's
optional ``trace[]`` field. Mirrors Cloudflare's ``validate-findings.cjs`` for
the SHAPE check, then goes one step further than the reference: when a codebase
target is pinned (``PENTEST_TARGET_PATH``), it RESOLVES each cited
``file:line`` against the on-disk repo and rejects a citation that points at a
file or line that does not exist — catching a hallucinated source location
*before* the expensive completion-time adjudication pass. (The Cloudflare
validator only checks JSON shape; it never stats the filesystem.)

Fires ONLY when a ``trace`` is present, so black-box findings — the majority of
Smith's multi-domain (web/API/network/AD/cloud/k8s/LLM) workload — are never
affected. Pure functions; the only side effect is reading files under the
pinned codebase root.

Shape contract (per step):
  kind         entrypoint | propagation | sink
  file         repo-relative path (str)
  line         positive int
  scope        bare function/method name (str — advisory, not resolved)
  description  factual description (str)

Sequence: >= 2 steps; first kind == entrypoint; last kind == sink.

File resolution uses line-RANGE tolerance (file exists + line within the file's
length, plus a few lines of slack), never content-exact matching — line drift
between when the agent read the code and when the trace is checked must never
cause a false rejection.
"""
from __future__ import annotations

import os

_VALID_KINDS = ("entrypoint", "propagation", "sink")

# Allow a citation a few lines past EOF: an agent may cite the line a function
# starts on after the file was trimmed, or count a trailing newline. A few lines
# of slack absorbs that drift without letting a wild "line 9999" citation pass.
_LINE_SLACK = 5


def repo_root() -> str | None:
    """The pinned codebase root, or None when this isn't a white-box scan."""
    path = os.environ.get("PENTEST_TARGET_PATH", "").strip()
    if path and os.path.isdir(path):
        return os.path.realpath(path)
    return None


def _resolve_in_repo(root: str, rel: str) -> str | None:
    """Resolve a cited path under ``root``; reject traversal outside it.

    Returns the absolute path when it exists as a file inside the repo, else
    None (missing file OR an attempt to escape the root — a finding citing
    ``../../etc/passwd`` is bogus and must not resolve).
    """
    if not rel or not isinstance(rel, str):
        return None
    candidate = os.path.realpath(os.path.join(root, rel.lstrip("/")))
    if candidate != root and not candidate.startswith(root + os.sep):
        return None
    return candidate if os.path.isfile(candidate) else None


def _count_lines(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _validate_step_shape(i: int, step) -> list[str]:
    """Shape errors for a single trace step (1-indexed in messages)."""
    if not isinstance(step, dict):
        return [f"step {i + 1}: must be an object with kind/file/line/scope/description"]
    errs: list[str] = []
    kind = str(step.get("kind", "")).strip().lower()
    if kind not in _VALID_KINDS:
        errs.append(
            f"step {i + 1}: kind '{step.get('kind', '')}' invalid — "
            f"use one of {', '.join(_VALID_KINDS)}"
        )
    if not str(step.get("file", "")).strip():
        errs.append(f"step {i + 1}: missing 'file'")
    line = step.get("line")
    # bool is a subclass of int — exclude it explicitly so True/False can't pass.
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        errs.append(f"step {i + 1}: 'line' must be a positive integer (got {line!r})")
    if not str(step.get("scope", "")).strip():
        errs.append(f"step {i + 1}: missing 'scope' (bare function/method name)")
    return errs


def _resolve_step(i: int, step: dict, root: str) -> list[str]:
    """Filesystem-resolution errors for one step against the codebase root."""
    rel = str(step.get("file", "")).strip()
    line = step.get("line")
    resolved = _resolve_in_repo(root, rel)
    if resolved is None:
        return [
            f"step {i + 1}: cited file '{rel}' does not exist under the codebase root "
            f"({root}) — verify the path or correct the citation"
        ]
    n = _count_lines(resolved)
    if isinstance(line, int) and not isinstance(line, bool) and line > n + _LINE_SLACK:
        return [
            f"step {i + 1}: cited line {line} is past the end of '{rel}' "
            f"({n} lines) — verify the line number"
        ]
    return []


def validate_finding_trace(trace) -> tuple[bool, list[str]]:
    """Validate an optional finding ``trace[]``. Returns ``(ok, errors)``.

    Two layers:
      1. SHAPE (always): a list of >= 2 steps; valid kind enum; file/line/scope
         present; the first step is an entrypoint and the last is a sink.
      2. RESOLUTION (white-box only — when ``PENTEST_TARGET_PATH`` is set): each
         cited file resolves under the repo root and the line is within the file
         (+ slack). A miss is a hallucinated source citation.

    Resolution only runs once the shape is clean, so the agent gets shape errors
    first, fixes them, and re-files before any filesystem check is attempted.
    """
    if not isinstance(trace, list):
        return False, ["'trace' must be a list of {kind, file, line, scope, description} steps"]
    if len(trace) < 2:
        return False, ["'trace' must have at least 2 steps (an entrypoint and a sink)"]

    errors: list[str] = []
    for i, step in enumerate(trace):
        errors.extend(_validate_step_shape(i, step))

    # Sequence rule — only meaningful once every step is a dict carrying a kind.
    if all(isinstance(s, dict) for s in trace):
        if str(trace[0].get("kind", "")).strip().lower() != "entrypoint":
            errors.append("first trace step must be kind 'entrypoint'")
        if str(trace[-1].get("kind", "")).strip().lower() != "sink":
            errors.append("last trace step must be kind 'sink'")

    root = repo_root()
    if root and not errors:
        for i, step in enumerate(trace):
            errors.extend(_resolve_step(i, step, root))

    return (not errors), errors
