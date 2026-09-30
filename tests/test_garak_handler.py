"""Unit tests for the garak handler's response_field auto-detect + probe
validation (mcp_server.scan_tools.handlers_ai). No Docker / network invoked."""
import pytest

import mcp_server.scan_tools.handlers_ai as h


# ── reply-field detection ─────────────────────────────────────────────────────
@pytest.mark.parametrize("data,expect", [
    ({"response": "hi"}, "$.response"),
    ({"reply": "hi"}, "$.reply"),
    ({"message": "hi"}, "$.message"),
    ({"choices": [{"message": {"content": "hi"}}]}, "$.choices[0].message.content"),
    ({"choices": [{"text": "hi"}]}, "$.choices[0].text"),
    ({"data": {"reply": "hi"}}, "$.data.reply"),
    ({"result": {"content": "hi"}}, "$.result.content"),
    ({"foo": 1}, ""),
    ("a string", ""),
    ({"response": ""}, ""),                       # empty string ignored
    ({"choices": []}, ""),                        # empty choices list
    ({"choices": [{"message": {}}]}, ""),         # choice without content/text
])
def test_pick_reply_field(data, expect):
    assert h._pick_reply_field(data) == expect


def test_is_reply_str():
    assert h._is_reply_str("x") is True
    assert h._is_reply_str("   ") is False
    assert h._is_reply_str(None) is False
    assert h._is_reply_str(5) is False


# ── probe-name validation ─────────────────────────────────────────────────────
_LIST_PROBES = """garak LLM vulnerability scanner v0.15.0
   probes: dan.AntiDAN
   probes: dan.Dan_11_0 💤
   probes: encoding.InjectBase64
   probes: xss.MarkdownImageExfil
"""


def test_parse_known_probes():
    classes, modules = h._parse_known_probes(_LIST_PROBES)
    assert modules == {"dan", "encoding", "xss"}
    assert "dan.Dan_11_0" in classes
    assert "probes" not in modules                # the 'probes:' label is not a module


def test_parse_known_probes_empty():
    assert h._parse_known_probes("") == (set(), set())


@pytest.mark.parametrize("req,kept,dropped", [
    ("dan,encoding,xss", "dan,encoding,xss", []),
    ("dan,bogus,dan.Dan_11_0", "dan,dan.Dan_11_0", ["bogus"]),
    ("nope", "", ["nope"]),
    ("dan, ,encoding,", "dan,encoding", []),      # blanks ignored
])
def test_filter_probes(req, kept, dropped):
    classes, modules = h._parse_known_probes(_LIST_PROBES)
    assert h._filter_probes(req, classes, modules) == (kept, dropped)


def test_filter_probes_passthrough_when_list_unknown():
    # empty known sets → couldn't learn the list → keep the request unchanged
    assert h._filter_probes("dan,whatever", set(), set()) == ("dan,whatever", [])


# ── REST-shape auto-detect: error-guided input key + reply field (aiohttp mocked) ─
class _MockResp:
    def __init__(self, status, text):
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._text


class _MockSession:
    """aiohttp session mock driven by `handler(json_body) -> (status, text)`."""
    def __init__(self, handler):
        self._handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, json=None, headers=None, timeout=None):
        return _MockResp(*self._handler(json or {}))


def _user_input_target(body):
    # mimics the real endpoint: needs `user_input`, replies {"response": "..."}
    if body.get("user_input"):
        return 200, '{"response": "Hello!"}'
    return 400, '{"error": "user_input is required"}'


@pytest.mark.parametrize("text,expect", [
    ('{"error":"user_input is required"}', ["user_input"]),
    ("missing field: prompt", ["prompt"]),
    ("required parameter 'q'", ["q"]),
    ("all good", []),
])
def test_fields_from_error(text, expect):
    assert h._fields_from_error(text) == expect


@pytest.mark.asyncio
async def test_autodetect_rest_shape_learns_from_error(monkeypatch):
    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: _MockSession(_user_input_target))
    body_key, field, diag = await h._autodetect_rest_shape("http://t/chat", {})
    assert body_key == "user_input"
    assert field == "$.response"
    assert diag == ""


@pytest.mark.asyncio
async def test_autodetect_rest_shape_miss_carries_diagnostic(monkeypatch):
    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession",
                        lambda *a, **k: _MockSession(lambda b: (400, '{"error":"nope"}')))
    body_key, field, diag = await h._autodetect_rest_shape("http://t/chat", {})
    assert body_key == ""
    assert field == ""
    assert "nope" in diag


@pytest.mark.asyncio
async def test_autodetect_rest_shape_failsoft(monkeypatch):
    import aiohttp

    def _boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(aiohttp, "ClientSession", _boom)
    assert await h._autodetect_rest_shape("http://t/chat", {}) == ("", "", "")


# ── _validated_probes / _resolved_rest_options (the handler wiring) ─────────
@pytest.mark.asyncio
async def test_validated_probes_drops_unknowns(monkeypatch):
    import tools.garak_runner as gr

    async def _lp():
        return _LIST_PROBES
    monkeypatch.setattr(gr, "list_probes", _lp)
    assert await h._validated_probes("dan,bogus,xss") == "dan,xss"


@pytest.mark.asyncio
async def test_validated_probes_keeps_original_if_all_dropped(monkeypatch):
    import tools.garak_runner as gr

    async def _lp():
        return _LIST_PROBES
    monkeypatch.setattr(gr, "list_probes", _lp)
    assert await h._validated_probes("nope1,nope2") == "nope1,nope2"


@pytest.mark.asyncio
async def test_validated_probes_failsoft(monkeypatch):
    import tools.garak_runner as gr

    async def _boom():
        raise RuntimeError("garak down")
    monkeypatch.setattr(gr, "list_probes", _boom)
    assert await h._validated_probes("dan,encoding") == "dan,encoding"


@pytest.mark.asyncio
async def test_resolved_rest_options_pins_both(monkeypatch):
    async def _shape(t, o):
        return ("user_input", "$.response", "")
    monkeypatch.setattr(h, "_autodetect_rest_shape", _shape)
    out = await h._resolved_rest_options("http://t/chat", {})
    assert out["body_key"] == "user_input"
    assert out["response_field"] == "$.response"


@pytest.mark.asyncio
async def test_resolved_rest_options_explicit_wins(monkeypatch):
    called = []

    async def _shape(t, o):
        called.append(1)
        return ("x", "y", "")
    monkeypatch.setattr(h, "_autodetect_rest_shape", _shape)
    opts = {"body_key": "m", "response_field": "$.r"}
    assert await h._resolved_rest_options("http://t/chat", opts) == opts
    assert called == []                       # both already pinned → no probing


@pytest.mark.asyncio
async def test_resolved_rest_options_miss_leaves_unset(monkeypatch):
    async def _shape(t, o):
        return ("", "", "user_input is required")
    monkeypatch.setattr(h, "_autodetect_rest_shape", _shape)
    out = await h._resolved_rest_options("http://t/chat", {})
    assert "body_key" not in out
    assert "response_field" not in out


def test_parse_known_probes_skips_probes_label():
    # a stray 'probes.<Class>' token is the label, not a module — skipped
    classes, modules = h._parse_known_probes("noise probes.Skip real.Class")
    assert "real" in modules and "probes" not in modules


@pytest.mark.asyncio
async def test_autodetect_rest_shape_reaches_target_but_no_reply_field(monkeypatch):
    import aiohttp

    def _handler(body):
        # error names 'user_input'; it returns 2xx but an unrecognised reply shape
        if body.get("user_input"):
            return 200, '{"weird": "no known reply key"}'
        return 400, '{"error": "user_input is required"}'

    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: _MockSession(_handler))
    body_key, field, diag = await h._autodetect_rest_shape("http://t/chat", {})
    assert body_key == "user_input"           # reached the target
    assert field == ""                         # but couldn't locate the reply field
    assert "reached the target" in diag
