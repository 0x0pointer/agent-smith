"""
Security taxonomy
=================
The injection/endpoint knowledge that drives coverage-matrix generation and
the cell-closure gates, in one place. Previously these tables were spread
across coverage/classify.py and coverage/validation.py and (for
BYPASS_REQUIRED_TYPES) re-imported from coverage by other modules — which
forced a circular-import workaround. As a **leaf** module (imports only the
stdlib ``re`` / ``json``), anything may depend on it without a cycle.

Consumers alias these (e.g. ``_APPLICABILITY = _tax.APPLICABILITY``) so their
existing local names are unchanged.
"""
from __future__ import annotations

import json
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
        # Role-confusion prompt injection (Ye/Cui/Hadfield-Menell, ICML 2026):
        # the model infers role from writing style, not from role tags, so
        # style-/delimiter-spoofed text is treated as a higher-privilege role.
        # Distinct cells from prompt_injection because the mechanism (and the
        # bypass to test) differs — see BYPASS_REQUIRED_TYPES below.
        "cot_forgery", "role_prefix_spoofing",
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

# ── Param-type normalization ─────────────────────────────────────────────────
# Smith (and spider/OpenAPI discovery) label params with many spellings for the
# same surface. Only the canonical keys above generate the right injection set, so
# a loosely-typed param silently degrades: a JSON-body param typed "json"/"body"
# never gets prototype/mass_assignment cells, and a form param typed "form" falls
# back to query/default and loses its xxe cell. Map the common aliases onto the
# canonical param types BEFORE fan-out. Unknown values pass through unchanged
# (classify._applicable_types then falls back to query/default as before).
PARAM_TYPE_ALIASES: dict[str, str] = {
    # form-encoded request bodies
    "form": "body_form", "formdata": "body_form", "form_data": "body_form",
    "urlencoded": "body_form", "x-www-form-urlencoded": "body_form",
    "multipart": "body_form", "multipart/form-data": "body_form",
    "post_form": "body_form", "body_urlencoded": "body_form",
    # JSON request bodies — "body" defaults to JSON (the modern API default); if it
    # was actually form-encoded the overlap (sqli/xss/ssti/ssrf/cmdi/nosqli) is still
    # covered, only xxe differs.
    "json": "body_json", "application/json": "body_json", "jsonbody": "body_json",
    "json_body": "body_json", "post_json": "body_json", "body": "body_json",
    # query string
    "querystring": "query", "query_string": "query", "qs": "query",
    "url_query": "query", "get": "query", "search": "query",
    # path / route segments
    "url": "path", "uri": "path", "route": "path", "segment": "path",
    "path_param": "path", "pathparam": "path", "url_path": "path",
    # headers / cookies
    "head": "header", "http_header": "header", "headers": "header", "cookies": "cookie",
    # AI / MCP surfaces
    "prompt": "llm_prompt", "chat": "llm_prompt", "message": "llm_prompt",
    "mcp_arg": "mcp_tool_arg", "mcp": "mcp_tool_arg",
}


def normalize_param_type(raw: str) -> str:
    """Canonicalize a param type so the coverage fan-out generates the right injection
    set. Case-insensitive; unknown types pass through unchanged (fan-out then falls
    back to query/default). See PARAM_TYPE_ALIASES for the rationale."""
    t = (raw or "").strip().lower()
    return PARAM_TYPE_ALIASES.get(t, t)

# ── Endpoint-type classification (path pattern → type tag), priority order ────
TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/graphql\b',                   re.IGNORECASE), "graphql"),
    (re.compile(r'/graph\b',                     re.IGNORECASE), "graphql"),
    # OAuth2 / OIDC authorization surfaces → the oauth-security specialist (plus
    # credential-audit). MUST precede the generic auth pattern below (first match
    # wins) so an /oauth, /authorize, /token, /userinfo or OIDC-discovery path does
    # NOT fall into the generic credential-audit-only auth gate and skip the
    # oauth-security deep assessment entirely.
    (re.compile(r'/(?:oauth2?|authorize|authorization|userinfo|introspect|revoke|token|openid)\b'
                r'|/\.well-known/openid-configuration\b', re.IGNORECASE), "oauth"),
    # SAML / enterprise-SSO / SCIM surfaces → the saml-sso specialist (plus
    # credential-audit). Also precedes generic auth. Matches SAMLRequest/SAMLResponse
    # when they appear in the classified path/query, not just the obvious /saml route.
    (re.compile(r'/(?:saml2?|sso|acs|sls|scim)\b|\bsaml(?:request|response)\b', re.IGNORECASE), "saml"),
    # Generic auth (login / registration / session) → credential-audit. OAuth and
    # SAML are split out above so they reach their specialists; everything else here.
    (re.compile(r'/(?:login|logout|signin|signup|register|auth)\b', re.IGNORECASE), "auth"),
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

# ── Value ranking for test ordering (WF-A1) ───────────────────────────────────
# An experienced tester front-loads the highest-value surface (auth, admin,
# payment, object-reference endpoints) and defers static/low-value ones. Lower
# rank = tested earlier. Keyed by the classify_endpoint() tag; unclassified
# endpoints fall to the default and are pulled forward only by a high-value param.
ENDPOINT_VALUE_RANK: dict[str, int] = {
    "financial":  0,   # payment / transfer / balance — crown jewels
    "auth":       1,   # login / registration / session
    "oauth":      1,   # OAuth2 / OIDC authorization surface
    "saml":       1,   # SAML / enterprise SSO / SCIM
    "admin":      1,
    "ai-redteam": 2,
    "graphql":    2,
    "upload":     3,
    "api":        4,
    "websocket":  4,
}
ENDPOINT_VALUE_DEFAULT = 6

# Param names that mark an endpoint as higher-value regardless of its path —
# object references, identity, and secrets are where authz/IDOR bugs live.
HIGH_VALUE_PARAM_TOKENS: frozenset[str] = frozenset({
    "id", "uid", "user", "userid", "user_id", "account", "accountid", "account_id",
    "role", "admin", "token", "key", "apikey", "api_key", "password", "secret",
    "order", "orderid", "order_id", "object", "objectid", "object_id", "ref",
    "owner", "tenant", "org", "orgid", "customer", "customerid",
})

# ── Name-aware param refinement (AR-B4) ───────────────────────────────────────
# A param whose NAME unambiguously implies its purpose does not need the broad
# type-based fan-out — a redirect_uri getting sqli/ssti/cmdi cells is pure noise
# that inflates the matrix (root cause of 700-cell matrices) and dilutes signal.
# DELIBERATELY CONSERVATIVE: only NARROW-INTENT names refine (redirect / url /
# file / command). Generic content params (q, search, name, id, email, data,
# comment) keep the full fan-out — their attack surface really is broad, and
# over-pruning would be a coverage regression. First match wins; the refined set
# is INTERSECTED with the type's applicable set, so refinement can only ever
# narrow, never add a nonsensical-for-type cell.
NAME_REFINEMENTS: list[tuple[tuple[str, ...], list[str]]] = [
    (("redirect", "redir", "returnurl", "return_url", "returnto", "return_to",
      "callback", "goto", "continue", "successurl", "success_url", "backurl"),
     ["redirect", "ssrf", "xss"]),
    (("url", "uri", "link", "webhook", "proxy", "fetch", "feed", "remote",
      "callbackurl", "imageurl", "image_url", "avatarurl"),
     ["ssrf", "redirect", "crlf"]),
    (("file", "filename", "filepath", "path", "template", "include",
      "download", "upload", "attachment", "document", "load"),
     ["traversal", "ssti", "xxe", "lfi"]),
    (("cmd", "command", "exec", "execute", "shell", "cmdline", "ping"),
     ["cmdi", "ssti"]),
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
    "cot_forgery":      "forged <think> reasoning block styled in the target's OWN reasoning voice (captured in recon); a generic block is not equivalent and is heavily under-effective",
    "role_prefix_spoofing": "forged turn delimiters (User:/Assistant:/System:/tool-output) tested in user input AND in tool-returned/RAG content, across delimiter variants",
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
    "cot_forgery", "role_prefix_spoofing",
    "mcp_command_injection", "mcp_intent_subversion", "mcp_context_oversharing",
}

# ── AI/LLM response-shape detection (companion to classify_endpoint) ──────────
# The path-keyword classifier above can only recognise a NAMED AI route (/chat,
# /completions, /mcp, …). A non-standard AI path (``/api/assistant/ask``,
# ``/v2/query``) therefore never routes to ai-redteam and its LLM assessment
# never registers. When an endpoint's PROBE RESPONSE is in hand we can still
# recognise the surface from its SHAPE. DELIBERATELY CONSERVATIVE — a generic
# JSON API must NOT be misread as an LLM endpoint — so a positive classification
# requires one of these specific markers:
#   * an SSE stream (``text/event-stream`` content-type, or OpenAI streaming
#     ``data:`` frames carrying a chat.completion chunk / ``[DONE]`` sentinel);
#   * an OpenAI-style chat/completions object (``object`` == "chat.completion"
#     / ".chunk" / "text_completion", or ``choices[].message`` / ``choices[].delta``);
#   * an MCP / JSON-RPC 2.0 handshake (``protocolVersion`` + ``serverInfo`` /
#     ``capabilities``, or a ``"method": "initialize"`` request).
_AI_SSE_CT_RE = re.compile(r"text/event-stream", re.IGNORECASE)
# An SSE event frame: a line starting with one of the SSE field names, or a
# ``data:`` line opening a JSON object / the OpenAI ``[DONE]`` stream sentinel.
_AI_SSE_BODY_RE = re.compile(
    r"^\s*(?:event|id|retry):|^\s*data:\s*(?:\[DONE\]|\{)", re.IGNORECASE | re.MULTILINE)
_AI_CHAT_OBJECTS = {"chat.completion", "chat.completion.chunk", "text_completion"}


def _looks_like_chat_json(data: object) -> bool:
    """True if a decoded JSON body is an OpenAI-style chat/completions response."""
    if not isinstance(data, dict):
        return False
    if str(data.get("object") or "") in _AI_CHAT_OBJECTS:
        return True
    choices = data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        c0 = choices[0]
        msg = c0.get("message")
        if isinstance(msg, dict) and ("content" in msg or "role" in msg):
            return True
        if isinstance(c0.get("delta"), dict):
            return True
    return False


def _looks_like_mcp_json(data: object) -> bool:
    """True if a decoded JSON body is an MCP / JSON-RPC 2.0 handshake."""
    if not isinstance(data, dict):
        return False
    if str(data.get("jsonrpc")) == "2.0":
        if data.get("method") == "initialize":
            return True
        res = data.get("result")
        if isinstance(res, dict) and {"protocolVersion", "serverInfo", "capabilities"} & set(res):
            return True
    # A bare MCP initialize result / server descriptor (no JSON-RPC envelope).
    if "protocolVersion" in data and (
            isinstance(data.get("serverInfo"), dict) or isinstance(data.get("capabilities"), dict)):
        return True
    return False


def classify_ai_response(status: int, content_type: str, body: str) -> str | None:
    """Return ``"ai-redteam"`` when a probe RESPONSE looks like an AI/LLM/MCP surface,
    else ``None`` — the shape-sniff companion to the path-based ``classify_endpoint``,
    for the many AI routes a keyword list can't name.

    Conservative by construction (see the markers above): an ordinary JSON API,
    an empty body, or a non-2xx response is never classified as AI.
    """
    try:
        if not (200 <= int(status) < 300):
            return None
    except (TypeError, ValueError):
        return None
    if _AI_SSE_CT_RE.search(content_type or ""):
        return "ai-redteam"
    text = body or ""
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if _looks_like_chat_json(data) or _looks_like_mcp_json(data):
            return "ai-redteam"
    # SSE framing carrying an OpenAI streaming payload (when no content-type is in hand).
    if _AI_SSE_BODY_RE.search(text) and (
            "chat.completion" in text or '"choices"' in text or "[DONE]" in text):
        return "ai-redteam"
    return None
