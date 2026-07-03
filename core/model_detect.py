"""
Model → profile auto-detection
==============================
Smith is BYO-LLM and client-agnostic, so the MCP server can't ask the client
"what model are you?". But the model name usually leaks into the process
environment (Ollama / opencode / SDK env vars), and that's enough to pick a SAFE
default context profile instead of always assuming a large-context frontier
model — which is what silently overflowed small local models before.

Resolution order (first hit wins) — every step is OVERRIDABLE:
  1. an explicit model_profile passed to session(action='start')
  2. SMITH_MODEL_PROFILE env (full|medium|small) — operator force-set
  3. a model name found in env (SMITH_MODEL, OPENCODE_MODEL, OLLAMA_MODEL,
     LLM_MODEL, MODEL, ANTHROPIC_MODEL, OPENAI_MODEL) → classify_model()
  4. a bare local-runtime signal (OLLAMA_HOST set, no model name) → 'small'
  5. nothing → 'full' (preserves today's default for cloud Claude Code runs,
     which set none of these signals — zero regression for the common case)

Conservative by design: a detected LOCAL model defaults to 'small' unless it's
clearly a big one, because the failure we're preventing (silent context
overflow, then an unrecoverable completion loop) costs far more than the failure
we might cause (a capable local model throttled one notch — fixed with one flag).
"""
from __future__ import annotations

import os
import re

VALID_PROFILES = ("full", "medium", "small")

# Cloud / frontier families — large context, strong instruction-following → full.
_FRONTIER = (
    "claude", "gpt-4", "gpt-5", "gpt4", "o1", "o3", "o4", "chatgpt",
    "gemini-1.5", "gemini-2", "gemini-exp", "gemini-pro", "grok",
)
# Open-weight / local families — size-dependent, usually a small context window.
_LOCAL = (
    "qwen", "llama", "codellama", "mistral", "mixtral", "gemma", "phi",
    "deepseek", "codestral", "starcoder", "granite", "command-r", "yi-",
    "solar", "openchat", "vicuna", "wizard", "hermes", "nous", "dolphin",
    "tinyllama", "stablelm", "falcon", "mpt-", "orca", "smollm", "olmo",
)
# Env vars that may carry the model name — client-specific ones first so an
# opencode/Ollama model wins over a stray global OPENAI_MODEL.
_MODEL_ENV_VARS = (
    "SMITH_MODEL", "OPENCODE_MODEL", "OLLAMA_MODEL",
    "LLM_MODEL", "MODEL", "ANTHROPIC_MODEL", "OPENAI_MODEL",
)

# Local models at/above this parameter count get 'medium' (better instruction
# adherence, often run on larger-context rigs); below it → 'small'.
_MEDIUM_PARAM_THRESHOLD_B = 65.0


def _parse_params_billions(name: str) -> float | None:
    """Extract a parameter count in billions, e.g. 'qwen2.5:32b' → 32.0."""
    m = re.search(r"(\d+(?:\.\d+)?)\s*b\b", name)
    return float(m.group(1)) if m else None


def classify_model(name: str) -> tuple[str | None, str]:
    """Map a model name to a profile. Returns (profile|None, reason).

    None means "not recognised" — the caller falls through to the next signal.
    """
    n = (name or "").strip().lower()
    if not n:
        return None, "empty model name"
    if any(f in n for f in _FRONTIER):
        return "full", f"frontier model '{name}' -> full"
    if any(local in n for local in _LOCAL):
        b = _parse_params_billions(n)
        if b is not None and b >= _MEDIUM_PARAM_THRESHOLD_B:
            return "medium", f"large local model '{name}' (~{b:g}B) -> medium"
        size = f" (~{b:g}B)" if b is not None else ""
        return "small", f"local model '{name}'{size} -> small (conservative)"
    return None, f"unrecognised model '{name}'"


def _detected_context_window() -> int | None:
    """The model's TRUE context window in tokens, if known (SM-2).

    Read from SMITH_CONTEXT_WINDOW — exported by the opencode installer, which
    queries the model server's /v1/models (max_model_len/context_length). Returns
    None when unknown, so profile resolution falls back to the name-based guess."""
    raw = os.environ.get("SMITH_CONTEXT_WINDOW", "").strip()
    try:
        n = int(raw)
        return n if n > 0 else None
    except ValueError:
        return None


def detect_profile(explicit: str | None = None) -> tuple[str, str]:
    """Resolve the model profile. Returns (profile, reason)."""
    if explicit and explicit.strip().lower() in VALID_PROFILES:
        return explicit.strip().lower(), "explicit model_profile option"

    forced = os.environ.get("SMITH_MODEL_PROFILE", "").strip().lower()
    if forced in VALID_PROFILES:
        return forced, "SMITH_MODEL_PROFILE env"

    # SM-2: the MEASURED context window (the installer detects it from the model
    # server; exported as SMITH_CONTEXT_WINDOW) is a far better profile signal
    # than an env-var model-name guess — a local 27B behind a generic proxy sets
    # no recognizable name and would otherwise fall through to `full` and overflow.
    # A detected window drives the profile directly, ranking ABOVE the name match.
    win = _detected_context_window()
    if win:
        if win <= 49_152:      # ≤ ~48k tokens
            return "small", f"detected context window {win} -> small"
        if win <= 131_072:     # ≤ ~128k tokens
            return "medium", f"detected context window {win} -> medium"
        return "full", f"detected context window {win} -> full"

    for var in _MODEL_ENV_VARS:
        val = os.environ.get(var, "").strip()
        if val:
            profile, reason = classify_model(val)
            if profile:
                return profile, f"{var}={val}: {reason}"

    if os.environ.get("OLLAMA_HOST", "").strip():
        return "small", "OLLAMA_HOST set (local runtime) -> small (conservative)"

    return "full", "no model signal -> full (default)"
