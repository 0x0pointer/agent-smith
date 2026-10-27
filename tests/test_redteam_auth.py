"""Auth-header sourcing + live cookie jar for the AI red-team transports (issue #247).

Covers core.auth_headers (resolve_headers, named profiles, CookieJar) and an
end-to-end check that redteam_tools._http_send_fn tracks a server that rotates its
session cookie on every response.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import auth_headers as a


@pytest.fixture
def fake_assets(monkeypatch):
    ka = {
        "auth_tokens": [{"value": "JWT_OLD"}, {"value": "JWT_NEW"}],
        "session_cookies": [{"name": "sid", "value": "abc"},
                            {"name": "csrftoken", "value": "tok1"}],
        "auth_profiles": {"tenantA": {"X-Tenant": "A", "Authorization": "Bearer PROF"}},
    }
    import core.session as s
    monkeypatch.setattr(s, "get", lambda: {"known_assets": ka}, raising=False)
    return ka


# ── resolve_headers ─────────────────────────────────────────────────────────────

def test_resolve_headers_sources_from_known_assets(fake_assets):
    h = a.resolve_headers({"headers_from": "known_assets"}, {"Content-Type": "application/json"})
    assert h["Authorization"] == "Bearer JWT_NEW"           # newest token
    assert "sid=abc" in h["Cookie"] and "csrftoken=tok1" in h["Cookie"]
    assert h["Content-Type"] == "application/json"


def test_resolve_headers_explicit_overrides_assets(fake_assets):
    h = a.resolve_headers({"headers_from": "known_assets",
                           "headers": {"Authorization": "Bearer MANUAL"}})
    assert h["Authorization"] == "Bearer MANUAL"            # explicit wins
    assert "sid=abc" in h["Cookie"]                         # but cookie still sourced


def test_resolve_headers_named_profile(fake_assets):
    h = a.resolve_headers({"auth_profile": "tenantA"})
    assert h == {"X-Tenant": "A", "Authorization": "Bearer PROF"}


def test_resolve_headers_no_profile_is_backcompat(fake_assets):
    # no headers_from → behaves exactly like the old static path (no asset leak-in)
    h = a.resolve_headers({"headers": {"X-Api-Key": "k"}}, {"Content-Type": "application/json"})
    assert h == {"Content-Type": "application/json", "X-Api-Key": "k"}


def test_wants_assets():
    assert a.wants_assets({"headers_from": "known_assets"})
    assert a.wants_assets({"auth_profile": "tenantA"})
    assert not a.wants_assets({"headers": {"Cookie": "x=1"}})


# ── cookie jar ──────────────────────────────────────────────────────────────────

def test_parse_set_cookie_list_and_string():
    assert a.parse_set_cookie(["sid=NEW; Path=/; HttpOnly", "a=1"]) == [("sid", "NEW"), ("a", "1")]
    assert a.parse_set_cookie("sid=NEW; Path=/, a=1; Path=/") == [("sid", "NEW"), ("a", "1")]


def test_cookie_jar_seed_apply_rotate(monkeypatch):
    monkeypatch.setattr("core.session.update_known_assets", lambda *a, **k: None, raising=False)
    jar = a.CookieJar.from_headers({"Cookie": "sid=abc; csrftoken=tok1"}, source_url="http://t/")
    assert jar.apply({})["Cookie"] == "sid=abc; csrftoken=tok1"
    changed = jar.update_from_response(["sid=NEW1; Path=/; HttpOnly"])
    assert changed == ["sid"]
    assert "sid=NEW1" in jar.apply({})["Cookie"]            # rotated value now sent
    assert "csrftoken=tok1" in jar.apply({})["Cookie"]      # untouched cookie kept


def test_cookie_jar_deletion_drops_cookie():
    jar = a.CookieJar({"sid": "abc"})
    jar.update_from_response(["sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"], persist=False)
    assert "sid" not in jar.jar


def test_cookie_jar_persists_session_cookies(monkeypatch):
    calls = []
    monkeypatch.setattr("core.session.update_known_assets",
                        lambda kind, rows: calls.append((kind, rows)), raising=False)
    jar = a.CookieJar(source_url="http://t/")
    jar.update_from_response(["sessionid=xyz; Path=/", "analytics=zzz"])   # only session-ish persists
    assert calls and calls[0][0] == "session_cookies"
    names = {r["name"] for r in calls[0][1]}
    assert "sessionid" in names and "analytics" not in names


# ── end-to-end: _http_send_fn tracks a rotating cookie ──────────────────────────

class _RotatingHandler(BaseHTTPRequestHandler):
    counter = 0

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        seen = ""
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("sessionid="):
                seen = part.strip()[len("sessionid="):]
        type(self).counter += 1
        new_sid = f"sid{type(self).counter}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", f"sessionid={new_sid}; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(json.dumps({"reply": f"saw={seen}"}).encode())


def test_retry_after_delay_honours_header_and_caps():
    import mcp_server.redteam_tools as rt

    class H:
        def __init__(self, v):
            self._v = v
        def get(self, k):
            return self._v
    assert rt._retry_after_delay(H("2"), 1) == 2.0
    assert rt._retry_after_delay(H(None), 2) == 4.0            # exponential fallback
    assert rt._retry_after_delay(H("9999"), 1) == rt._BACKOFF_CAP   # capped
    assert rt._retry_after_delay(H("Wed, 21 Oct 2099 07:28:00 GMT"), 1) == 2.0  # date → expo


class _RateLimitHandler(BaseHTTPRequestHandler):
    seen = 0

    def log_message(self, *a):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).seen += 1
        if type(self).seen == 1:                 # first call: rate-limit, then recover
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"reply": "recovered"}).encode())


def test_http_send_fn_backs_off_and_retries_on_429(monkeypatch):
    monkeypatch.setattr("core.session.get", lambda: None, raising=False)
    srv = HTTPServer(("127.0.0.1", 0), _RateLimitHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        import mcp_server.redteam_tools as rt
        send = rt._http_send_fn(f"http://127.0.0.1:{srv.server_address[1]}/chat", {})
        assert send("hello") == "recovered"      # retried past the 429 instead of failing
    finally:
        srv.shutdown()


def test_http_send_fn_follows_cookie_rotation(monkeypatch):
    monkeypatch.setattr("core.session.update_known_assets", lambda *a, **k: None, raising=False)
    monkeypatch.setattr("core.session.get",
                        lambda: {"known_assets": {"session_cookies": [{"name": "sessionid", "value": "sid0"}]}},
                        raising=False)
    srv = HTTPServer(("127.0.0.1", 0), _RotatingHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/chat"
        import mcp_server.redteam_tools as rt
        send = rt._http_send_fn(url, {"headers_from": "known_assets"})
        r1 = send("hello")              # sends sid0, server rotates to sid1
        r2 = send("again")              # should now send the rotated sessionid
        assert "saw=sid0" in r1
        # the jar refreshed from the first response's Set-Cookie (sessionid=sid1)
        assert "saw=sid1" in r2
    finally:
        srv.shutdown()
