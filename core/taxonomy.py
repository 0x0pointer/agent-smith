"""
Security taxonomy
=================
The injection/endpoint knowledge that drives coverage-matrix generation and
the cell-closure gates, in one place. Previously these tables were spread
across coverage/classify.py and coverage/validation.py and (for
BYPASS_REQUIRED_TYPES) re-imported from coverage by other modules — which
forced a circular-import workaround. As a **leaf** module (imports only
``re``), anything may depend on it without a cycle.

Consumers alias these (e.g. ``_APPLICABILITY = _tax.APPLICABILITY``) so their
existing local names are unchanged.
"""
from __future__ import annotations

import re

# ── Applicability: which injection types apply to each param type ─────────────
APPLICABILITY: dict[str, list[str]] = {
    # param_type/value_hint
    "path/integer":      ["sqli", "idor", "traversal"],
    "path/string":       ["sqli", "xss", "ssti", "traversal", "cmdi", "idor"],
    "query/default":     ["sqli", "xss", "ssti", "ssrf", "cmdi", "traversal", "redirect", "nosqli", "crlf"],
    "body_form/default": ["sqli", "xss", "ssti", "ssrf", "cmdi", "xxe", "nosqli"],
    "body_json/default": ["sqli", "nosqli", "xss", "ssti", "ssrf", "cmdi", "prototype", "mass_assignment"],
    "header/default":    ["crlf", "xss", "ssrf", "smuggling"],
    "cookie/default":    ["sqli", "xss", "deserial"],
    "endpoint/default":  ["cors", "csrf", "security_headers", "rate_limit", "method_tampering", "cache", "jwt", "race", "bfla"],

    # ── AI / LLM / MCP surfaces ───────────────────────────────────────────────
    # An LLM chat/prompt parameter fans out to the runtime-testable OWASP LLM
    # Top 10 (2025) categories. Cross-tagged to AITG APP-*/MOD-* and AISVS
    # C2/C7/C9/C11 in the ai-redteam skill. Register the prompt field with
    # type="llm_prompt" to generate these.
    "llm_prompt/default": [
        "prompt_injection", "jailbreak", "system_prompt_leak",
        "sensitive_info_disclosure", "improper_output_handling",
        "excessive_agency", "misinformation", "unbounded_consumption",
        "model_extraction", "content_bias", "membership_inference",
    ],
    # An MCP tool argument fans out to the OWASP MCP Top 10 runtime categories.
    # Register each MCP tool's string args with type="mcp_tool_arg".
    "mcp_tool_arg/default": [
        "mcp_token_exposure", "mcp_scope_creep", "mcp_tool_poisoning",
        "mcp_command_injection", "mcp_intent_subversion", "mcp_auth",
        "mcp_context_oversharing",
    ],
    # Endpoint-level LLM weaknesses (apply per-endpoint, not per-param). Added
    # to the endpoint-level cell set when classify_endpoint() tags an endpoint
    # "ai-redteam" (see coverage/operations.add_endpoint).
    "llm_endpoint/default": ["rag_poisoning", "embedding_manipulation"],
}

# Fallback: if no specific hint matches, use param_type/default
FALLBACK_KEY = "{type}/default"

# ── Endpoint-type classification (path pattern → type tag), priority order ────
TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/graphql\b',                   re.IGNORECASE), "graphql"),
    (re.compile(r'/graph\b',                     re.IGNORECASE), "graphql"),
    (re.compile(r'/(?:login|logout|signin|signup|register|auth|oauth|token|sso)\b', re.IGNORECASE), "auth"),
    (re.compile(r'/admin\b',                     re.IGNORECASE), "admin"),
    (re.compile(r'/(?:upload|file|attachment|media|import)\b', re.IGNORECASE), "upload"),
    (re.compile(r'/(?:payment|invoice|checkout|billing|transaction|transfer|balance|wallet)\b', re.IGNORECASE), "financial"),
    (re.compile(r'/(?:ws|websocket|socket)\b', re.IGNORECASE), "websocket"),
    # AI/LLM + MCP endpoints — placed BEFORE the generic /api|/v\d+ pattern so an
    # LLM chat or MCP endpoint opens the ai-redteam gate instead of being
    # misclassified as a plain API. Conservative over-trigger is intentional:
    # better to make ai-redteam mandatory than to silently skip the AI surface.
    (re.compile(r'/(?:chat|completions|messages|generate|embeddings|converse|responses)\b', re.IGNORECASE), "ai-redteam"),
    (re.compile(r'/(?:mcp|sse)\b|/tools/(?:list|call)\b', re.IGNORECASE), "ai-redteam"),
    (re.compile(r'(?:/api\b|/v\d+\b)',                  re.IGNORECASE), "api"),
]

# ── Injection types with known bypass techniques — marking these N/A requires
# the notes to explain WHY the bypass doesn't apply. ──────────────────────────
BYPASS_REQUIRED_TYPES: dict[str, str] = {
    "xxe":  "Content-Type switching to application/xml",
    "sqli": "blind boolean/time-based, second-order, or encoding bypass",
    "xss":  "encoding bypass, DOM sinks, or stored via other endpoint",
    "ssti": "alternative template syntax (${}, <%%>, #{}, *{})",
    # LLM categories with well-known bypasses — marking N/A must explain why the
    # bypass doesn't apply (techniques documented in the ai-redteam skill).
    "prompt_injection": "encoding (base64/ROT13/homoglyph/Unicode-tag), multi-language, authority-marker rotation, or multi-objective payloads",
    "jailbreak":        "crescendo multi-turn, DAN/role-play framing, refusal-suppression, or many-shot",
}

# ── Injection cell types where 401/403 is meaningless evidence of cleanliness
# (auth blocked the payload). Excludes auth/access-control types where 401/403
# IS the finding signal. ──────────────────────────────────────────────────────
AUTH_GATED_TYPES = {
    "sqli", "nosqli", "xss", "ssti", "cmdi", "ssrf", "xxe",
    "traversal", "crlf", "prototype", "mass_assignment", "redirect",
    # LLM prompt-evaluation cells: a 401/403 means auth blocked the payload,
    # not that the model filtered it. The ai-redteam skill mandates dual
    # auth-state testing, so these must be re-tested under auth before closing.
    "prompt_injection", "jailbreak", "system_prompt_leak",
    "sensitive_info_disclosure", "improper_output_handling", "excessive_agency",
    "mcp_command_injection", "mcp_intent_subversion", "mcp_context_oversharing",
}
