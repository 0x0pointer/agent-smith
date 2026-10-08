"""HTTP transport for the red-team engine — status-aware, rate-limited, session-aware.

The engine's contract is `send_fn(message, conversation_id=None) -> str`. A naive
sender that turns every HTTPError into an opaque string makes a gateway block
(HTTP 500/403), a dead session (401) and a rate limit (429) indistinguishable from
a model reply — so a run against an expired cookie looks "clean". This module keeps
that contract but:

  * encodes transport failures as ``[send error: HTTP <code> <body>]`` so the
    oracle can score them as NOT-reached-model (``transport_error``);
  * keeps a per-attempt HTTP status histogram (``codes``) so results can report
    reached-model vs blocked, not a bare attempt count;
  * throttles per target host (optional RPS budget, shared across every sender in
    the process) and backs off on 429/503 honouring ``Retry-After`` — a rate-limited
    attempt is RETRIED, never counted as a miss;
  * carries session auth: ``headers_from="known_assets"`` pulls the freshest JWT +
    session cookies captured during the scan, and ``Set-Cookie`` on every response
    rotates the jar (sliding/rotating cookie sessions stay alive);
  * can deliver a document/file carrier as multipart/form-data (``send_file``);
  * reads streaming replies: a ``text/event-stream`` (SSE) body is reassembled from
    its ``data:`` token events, with tool/status events appended as a
    ``[stream events]`` trailer (they are the excessive-agency evidence);
  * fetches a CSRF token before each send when ``csrf`` is configured (JSON key or
    ``<meta name="csrf-token">``), re-fetching once on a 403/419.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter

_ERR_RE = re.compile(r"^\[send error: (?:HTTP (\d{3})\b)?")

# Transport classes the oracle distinguishes. Only "ok" reached the model.
OK, BLOCKED, AUTH_FAILURE, RATE_LIMITED, UNREACHABLE = (
    "ok", "blocked", "auth_failure", "rate_limited", "unreachable")

_RETRY_CODES = {429, 503}
_MAX_BACKOFF_S = 60.0


def transport_error(text) -> dict | None:
    """Classify a sender reply. None when the reply is a real model response;
    otherwise ``{"code": int|None, "transport": blocked|auth_failure|rate_limited|unreachable}``."""
    if not isinstance(text, str):
        return None
    m = _ERR_RE.match(text)
    if not m:
        return None
    code = int(m.group(1)) if m.group(1) else None
    if code is None:
        kind = UNREACHABLE
    elif code in (401, 407):
        kind = AUTH_FAILURE
    elif code == 429:
        kind = RATE_LIMITED
    else:
        kind = BLOCKED
    return {"code": code, "transport": kind}


def reply_code(text) -> int | None:
    """HTTP status of a sender reply — 200 for a model reply, the error code for a
    transport error, None when the target was unreachable."""
    te = transport_error(text)
    return 200 if te is None else te["code"]


# ── per-host throttle + backoff (process-wide, shared by every sender) ────────

class _Throttle:
    def __init__(self):
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}       # host -> earliest next send (monotonic)
        self.stats: dict[str, dict] = {}        # host -> {rate_limited, last_retry_after}

    def wait(self, host: str, rps: float | None) -> None:
        if not rps or rps <= 0:
            with self._lock:
                nxt = self._next.get(host, 0.0)
            delay = nxt - time.monotonic()
        else:
            with self._lock:
                now = time.monotonic()
                slot = max(now, self._next.get(host, 0.0))
                self._next[host] = slot + 1.0 / rps
            delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(min(delay, _MAX_BACKOFF_S))

    def backoff(self, host: str, seconds: float) -> None:
        seconds = max(0.0, min(seconds, _MAX_BACKOFF_S))
        with self._lock:
            self._next[host] = max(self._next.get(host, 0.0), time.monotonic() + seconds)
            st = self.stats.setdefault(host, {"rate_limited": 0, "last_retry_after": None})
            st["rate_limited"] += 1
            st["last_retry_after"] = round(seconds, 2)


THROTTLE = _Throttle()


def _retry_after(headers, attempt: int) -> float:
    ra = (headers or {}).get("Retry-After") if headers else None
    if ra:
        try:
            return float(ra)
        except ValueError:
            pass
    return min(_MAX_BACKOFF_S, 2.0 ** attempt)


def default_rps() -> float | None:
    try:
        v = float(os.environ.get("SMITH_TARGET_RPS", "") or 0)
        return v if v > 0 else None
    except ValueError:
        return None


# ── session auth from known_assets ────────────────────────────────────────────

def known_asset_headers() -> dict:
    """Freshest captured auth from the scan: latest JWT as Bearer + session cookies.
    Empty when the scan holds none (or no scan is active)."""
    try:
        from core import session as scan_session
        ka = (scan_session.get() or {}).get("known_assets") or {}
    except Exception:
        return {}
    headers: dict = {}
    toks = ka.get("auth_tokens") or []
    if toks and isinstance(toks[-1], dict) and toks[-1].get("value"):
        headers["Authorization"] = f"Bearer {toks[-1]['value']}"
    pairs = [f"{c['name']}={c.get('value', '')}" for c in (ka.get("session_cookies") or [])
             if isinstance(c, dict) and c.get("name")]
    if pairs:
        headers["Cookie"] = "; ".join(pairs)
    return headers


def resolve_headers(opts: dict) -> dict:
    """Explicit ``headers`` win over ``headers_from="known_assets"`` (merged under them)."""
    base = known_asset_headers() if opts.get("headers_from") == "known_assets" else {}
    extra = opts.get("headers") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except ValueError:
            extra = {}
    return {**base, **{str(k): str(v) for k, v in (extra or {}).items()}}


def _parse_cookie_header(value: str) -> dict:
    out: dict = {}
    for part in (value or "").split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            if k:
                out[k] = v
    return out


def _set_cookie_pairs(headers) -> dict:
    out: dict = {}
    for raw in (headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else None) or []:
        pair = raw.split(";", 1)[0]
        if "=" in pair:
            k, _, v = pair.partition("=")
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def _persist_rotated_cookies(pairs: dict, url: str) -> None:
    try:
        from datetime import datetime, timezone

        from core import session as scan_session
        now = datetime.now(timezone.utc).isoformat()
        scan_session.update_known_assets("session_cookies", [
            {"name": k, "value": v, "source_url": url, "obtained_at": now} for k, v in pairs.items()])
    except Exception:
        pass


# ── CSRF token ────────────────────────────────────────────────────────────────

_META_CSRF_RE = re.compile(
    r'<meta[^>]+name=["\'](?:csrf-token|csrf_token|_csrf|csrf)["\'][^>]*content=["\']([^"\']+)'
    r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\'](?:csrf-token|csrf_token|_csrf|csrf)["\']',
    re.I)


def _csrf_from_body(raw: bytes, json_key: str | None) -> str | None:
    """Token from a JSON body (dotted ``json_key``) or an HTML ``<meta name=csrf-token>``."""
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if data is not None:
        if json_key:
            cur = data
            for part in json_key.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            return cur if isinstance(cur, str) and cur else None
        # auto: first well-known key, breadth-first through nested objects
        queue = [data]
        while queue:
            cur = queue.pop(0)
            if not isinstance(cur, dict):
                continue
            for key in ("csrf_token", "csrfToken", "csrf", "_csrf", "xsrf_token"):
                if isinstance(cur.get(key), str) and cur[key]:
                    return cur[key]
            queue.extend(v for v in cur.values() if isinstance(v, dict))
        return None
    m = _META_CSRF_RE.search(text)
    return (m.group(1) or m.group(2)) if m else None


def _csrf_config(opt) -> dict | None:
    """Normalise the ``csrf`` option: a URL string, or {url, header, json_key, refresh}."""
    if not opt:
        return None
    if isinstance(opt, str):
        try:
            opt = json.loads(opt)
        except ValueError:
            opt = {"url": opt}
    if not isinstance(opt, dict) or not opt.get("url"):
        return None
    return {"url": opt["url"], "header": opt.get("header", "X-CSRF-Token"),
            "json_key": opt.get("json_key"),
            "refresh": opt.get("refresh", "always")}      # always | on_error


# ── the sender ────────────────────────────────────────────────────────────────

# SSE event "type" values that carry reply text; anything else typed (status,
# tool_call, done, …) is an out-of-band event, not model output.
_SSE_TEXT_TYPES = {"token", "text", "delta", "content", "chunk", "message",
                   "text_delta", "content_block_delta", "response.output_text.delta"}
_SSE_TEXT_KEYS = ("content", "token", "text", "delta")


def _is_sse(raw: bytes, content_type: str) -> bool:
    if "text/event-stream" in (content_type or "").lower():
        return True
    head = raw.lstrip()[:64]
    return head.startswith(b"data:") or head.startswith(b"event:")


def _sse_text(ev, reply_key: str):
    """Reply text carried by one parsed SSE event, or None."""
    if isinstance(ev, str):
        return ev
    if not isinstance(ev, dict):
        return None
    if reply_key and isinstance(ev.get(reply_key), str):
        return ev[reply_key]
    ch = ev.get("choices")
    if isinstance(ch, list) and ch and isinstance(ch[0], dict):      # OpenAI-style chunk
        d = ch[0].get("delta") or ch[0].get("message") or {}
        return d.get("content") if isinstance(d, dict) else None
    for k in _SSE_TEXT_KEYS:
        v = ev.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, dict) and isinstance(v.get("text"), str):   # Anthropic-style delta
            return v["text"]
    return None


def _extract_sse(raw: bytes, reply_key: str) -> str:
    text: list[str] = []
    events: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            ev = json.loads(payload)
        except ValueError:
            text.append(payload)
            continue
        etype = ev.get("type") if isinstance(ev, dict) else None
        if etype is None or etype in _SSE_TEXT_TYPES:
            chunk = _sse_text(ev, reply_key)
            if chunk is not None:
                text.append(chunk)
                continue
        if etype in ("done", "end", "message_stop"):
            continue
        detail = _sse_text(ev, reply_key) if isinstance(ev, dict) else None
        events.append(f"{etype}: {detail}" if etype and detail else json.dumps(ev)[:300])
    out = "".join(text)
    if events:
        out += "\n\n[stream events]\n" + "\n".join(events)
    return out


def _extract_reply(raw: bytes, reply_key: str, content_type: str = "") -> str:
    if _is_sse(raw, content_type):
        return _extract_sse(raw, reply_key)
    try:
        data = json.loads(raw)
    except ValueError:
        return raw.decode("utf-8", "replace")
    if isinstance(data, dict):
        if reply_key and reply_key in data:
            v = data[reply_key]
            return v if isinstance(v, str) else json.dumps(v)
        return json.dumps(data)
    return json.dumps(data)


class HttpSender:
    """Callable ``send(message, conversation_id=None) -> str`` with a status
    histogram, rotating cookie jar, per-host throttle and 429/503 backoff."""

    def __init__(self, target: str, body_key: str = "message", reply_key: str = "reply",
                 headers: dict | None = None, rps: float | None = None,
                 max_retries: int = 3, timeout: float = 30.0, persist_cookies: bool = False,
                 extra_body: dict | None = None, csrf: dict | None = None):
        self.target = target
        self.body_key = body_key
        self.reply_key = reply_key
        hdrs = dict(headers or {})
        self._jar = _parse_cookie_header(hdrs.pop("Cookie", "") or hdrs.pop("cookie", ""))
        self._headers = hdrs
        self.rps = rps if rps is not None else default_rps()
        self.max_retries = max_retries
        self.timeout = timeout
        self.persist_cookies = persist_cookies
        self.extra_body = extra_body or {}
        self.host = urllib.parse.urlsplit(target).netloc or target
        self.codes: Counter = Counter()      # final status per delivered attempt
        self.retries = 0                     # 429/503 retries (not counted as attempts)
        self.last_code: int | None = None
        self.last_raw: bytes = b""
        self.csrf = csrf                     # normalised by _csrf_config, or None
        self._csrf_token: str | None = None

    # --- public -----------------------------------------------------------
    def __call__(self, message: str, conversation_id: str | None = None) -> str:
        body = {**self.extra_body, self.body_key: message}
        if conversation_id:
            body["conversation_id"] = conversation_id
        return self._send(json.dumps(body).encode(), {"Content-Type": "application/json"})

    def send_file(self, content: bytes, filename: str, content_type: str,
                  file_field: str = "file", form_fields: dict | None = None) -> str:
        """Deliver a document carrier as multipart/form-data."""
        boundary = f"----smith{uuid.uuid4().hex}"
        parts: list[bytes] = []
        for k, v in (form_fields or {}).items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
                      f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n').encode()
                     + content + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return self._send(b"".join(parts), {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    def stats(self) -> dict:
        return {"codes": {str(k): v for k, v in sorted(self.codes.items(), key=lambda kv: str(kv[0]))},
                "retries": self.retries,
                "rate_limit": THROTTLE.stats.get(self.host)}

    # --- internals --------------------------------------------------------
    def _request_headers(self, content_headers: dict) -> dict:
        h = {**self._headers, **content_headers}
        if self._jar:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._jar.items())
        return h

    def _absorb_cookies(self, headers) -> None:
        pairs = _set_cookie_pairs(headers) if headers is not None else {}
        if pairs:
            self._jar.update(pairs)
            if self.persist_cookies:
                _persist_rotated_cookies(pairs, self.target)

    def _fetch_csrf(self) -> None:
        """GET the configured token source with the current jar (absorbing any
        Set-Cookie — this also bootstraps a session) and remember the token."""
        req = urllib.request.Request(self.csrf["url"], None, self._request_headers({}))
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                self._absorb_cookies(r.headers)
        except urllib.error.HTTPError as e:
            self._absorb_cookies(e.headers)
            raw = _safe_read(e)
        except Exception:
            return
        self._csrf_token = _csrf_from_body(raw, self.csrf.get("json_key")) or self._csrf_token

    def _send(self, data: bytes, content_headers: dict) -> str:
        attempt = 0
        csrf_retried = False
        while True:
            THROTTLE.wait(self.host, self.rps)
            hdrs = dict(content_headers)
            if self.csrf:
                if self._csrf_token is None or self.csrf["refresh"] == "always":
                    self._fetch_csrf()
                if self._csrf_token:
                    hdrs[self.csrf["header"]] = self._csrf_token
            req = urllib.request.Request(self.target, data, self._request_headers(hdrs))
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read()
                    self._absorb_cookies(r.headers)
                    self._record(r.status or 200, raw)
                    return _extract_reply(raw, self.reply_key, r.headers.get("Content-Type", ""))
            except urllib.error.HTTPError as e:
                raw = _safe_read(e)
                self._absorb_cookies(e.headers)
                if self.csrf and e.code in (403, 419) and not csrf_retried:
                    csrf_retried = True          # stale token — refetch once, not an attempt
                    self._csrf_token = None
                    continue
                if e.code in _RETRY_CODES and attempt < self.max_retries:
                    self.retries += 1
                    THROTTLE.backoff(self.host, _retry_after(e.headers, attempt))
                    attempt += 1
                    continue
                self._record(e.code, raw)
                snippet = raw.decode("utf-8", "replace").strip().replace("\n", " ")[:300]
                return f"[send error: HTTP {e.code} {snippet}]" if snippet else f"[send error: HTTP {e.code}]"
            except Exception as e:      # connection refused / DNS / timeout
                self._record(None, b"")
                return f"[send error: {type(e).__name__}: {e}]"

    def _record(self, code, raw: bytes) -> None:
        self.last_code = code
        self.last_raw = raw
        self.codes[code if code is not None else "unreachable"] += 1


def _safe_read(e) -> bytes:
    try:
        return e.read() or b""
    except Exception:
        return b""


def sender_from_options(target: str, opts: dict, persist_cookies: bool = True) -> HttpSender:
    """Build an HttpSender from a redteam() options dict."""
    rps = opts.get("rps")
    return HttpSender(
        target, opts.get("body_key", "message"), opts.get("reply_key", "reply"),
        resolve_headers(opts),
        rps=float(rps) if rps not in (None, "") else None,
        max_retries=int(opts.get("max_retries", 3)),
        timeout=float(opts.get("timeout", 30)),
        persist_cookies=persist_cookies and opts.get("headers_from") == "known_assets",
        extra_body=opts.get("extra_body") if isinstance(opts.get("extra_body"), dict) else None,
        csrf=_csrf_config(opts.get("csrf")),
    )
