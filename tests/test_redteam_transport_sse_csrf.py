"""redteam transport — SSE (text/event-stream) replies and CSRF-token handling.

Shaped on the FinBot admin Co-Pilot: POST JSON {message}, X-CSRF-Token header taken
from a session-status endpoint, reply streamed as `data: {"type": "token", ...}`
events interleaved with `status` (tool-call) events. Before this, the sender returned
the raw SSE bytes and could not send the token, so feedback_attack/reproduce were
unusable against streaming agentic chats. Local in-process server only.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_server.redteam import transport

_SSE = (
    'data: {"type": "status", "content": "Thinking"}\n\n'
    'data: {"type": "token", "content": "Hello"}\n\n'
    'data: {"type": "token", "content": " world"}\n\n'
    'data: {"type": "status", "content": "Running systemutils read config"}\n\n'
    'data: {"type": "done"}\n\n'
)


@pytest.fixture
def finbot_like():
    """Session cookie on first contact; /status returns a rotating csrf_token; /chat
    requires the current token and streams SSE. `state` records what the server saw."""
    state = {"issued": [], "seen_tokens": [], "chat_cookies": []}

    class H(BaseHTTPRequestHandler):
        def _reply(self, status, body, ctype, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())

        def do_GET(self):
            tok = f"tok{len(state['issued'])}"
            state["issued"].append(tok)
            extra = {} if "sid=" in (self.headers.get("Cookie") or "") else {"Set-Cookie": "sid=s1; Path=/"}
            if self.path == "/page":
                self._reply(200, f'<html><head><meta name="csrf-token" content="{tok}"></head></html>',
                            "text/html", extra)
            else:
                self._reply(200, json.dumps({"session": {"csrf_token": tok}}), "application/json", extra)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            got = self.headers.get("X-CSRF-Token")
            state["seen_tokens"].append(got)
            state["chat_cookies"].append(self.headers.get("Cookie"))
            if not state["issued"] or got != state["issued"][-1]:
                self._reply(403, json.dumps({"detail": "CSRF token invalid"}), "application/json")
                return
            self._reply(200, _SSE, "text/event-stream")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    yield base, state
    srv.shutdown()


def test_sse_reply_reassembled_with_event_trailer():
    out = transport._extract_reply(_SSE.encode(), "reply", "text/event-stream")
    text, _, trailer = out.partition("\n\n[stream events]\n")
    assert text == "Hello world"
    assert "status: Running systemutils read config" in trailer
    assert "done" not in trailer


def test_sse_detected_without_content_type_and_openai_chunks():
    raw = (b'data: {"choices": [{"delta": {"content": "Hi"}}]}\n\n'
           b'data: {"choices": [{"delta": {"content": "!"}}]}\n\ndata: [DONE]\n\n')
    assert transport._extract_reply(raw, "reply") == "Hi!"


def test_json_reply_unchanged():
    assert transport._extract_reply(b'{"reply": "ok"}', "reply", "application/json") == "ok"


def test_csrf_from_json_key_and_meta():
    assert transport._csrf_from_body(b'{"a": {"csrf_token": "x"}}', "a.csrf_token") == "x"
    assert transport._csrf_from_body(b'{"csrf_token": "y"}', None) == "y"
    assert transport._csrf_from_body(b'<meta content="z" name="csrf-token">', None) == "z"
    assert transport._csrf_from_body(b'{"s": {"csrf_token": "n"}}', None) == "n"
    assert transport._csrf_from_body(b'{"nope": 1}', None) is None


def test_sender_fetches_csrf_bootstraps_session_and_reads_sse(finbot_like):
    base, state = finbot_like
    send = transport.sender_from_options(
        f"{base}/chat", {"csrf": {"url": f"{base}/status", "json_key": "session.csrf_token"}})
    assert send("hi").startswith("Hello world")
    assert send("again").startswith("Hello world")
    assert state["seen_tokens"] == ["tok0", "tok1"]         # refreshed per send (rotating)
    assert state["chat_cookies"][0] == "sid=s1"             # cookie from the token fetch reused
    assert send.codes[200] == 2 and 403 not in send.codes


def test_sender_csrf_from_html_meta(finbot_like):
    base, state = finbot_like
    send = transport.sender_from_options(f"{base}/chat", {"csrf": f"{base}/page"})
    assert send("hi").startswith("Hello world")
    assert state["seen_tokens"] == ["tok0"]


def test_stale_token_refetched_once_on_403(finbot_like):
    base, state = finbot_like
    send = transport.sender_from_options(
        f"{base}/chat", {"csrf": {"url": f"{base}/status", "refresh": "on_error"}})
    assert send("a").startswith("Hello world")
    state["issued"].append("rotated-elsewhere")             # server-side rotation
    assert send("b").startswith("Hello world")              # 403 -> refetch -> success
    assert state["seen_tokens"] == ["tok0", "tok0", "tok2"]
    assert 403 not in send.codes                            # the refetch is not an attempt


def test_no_csrf_option_sends_no_token(finbot_like):
    base, state = finbot_like
    out = transport.HttpSender(f"{base}/chat", max_retries=0)("hi")
    assert out.startswith("[send error: HTTP 403")
    assert state["seen_tokens"] == [None]
