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


# ── _autodetect_response_field (aiohttp mocked) ───────────────────────────────
class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self._payload


class _FakeSession:
    def __init__(self, payload):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, *a, **k):
        return _FakeResp(self._payload)


@pytest.mark.asyncio
async def test_autodetect_response_field_success(monkeypatch):
    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession",
                        lambda *a, **k: _FakeSession({"reply": "hello there"}))
    got = await h._autodetect_response_field("http://target/chat", {"body_key": "message"})
    assert got == "$.reply"


@pytest.mark.asyncio
async def test_autodetect_response_field_failsoft(monkeypatch):
    import aiohttp

    def _boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(aiohttp, "ClientSession", _boom)
    assert await h._autodetect_response_field("http://target/chat", {}) == ""


# ── _validated_probes / _resolved_response_field (the handler wiring) ─────────
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
async def test_resolved_response_field_explicit_wins():
    opts = {"response_field": "$.answer"}
    assert await h._resolved_response_field("http://t/chat", opts) == opts


@pytest.mark.asyncio
async def test_resolved_response_field_autodetects(monkeypatch):
    async def _detect(target, options):
        return "$.reply"
    monkeypatch.setattr(h, "_autodetect_response_field", _detect)
    out = await h._resolved_response_field("http://t/chat", {"body_key": "message"})
    assert out["response_field"] == "$.reply"


@pytest.mark.asyncio
async def test_resolved_response_field_miss_unchanged(monkeypatch):
    async def _detect(target, options):
        return ""
    monkeypatch.setattr(h, "_autodetect_response_field", _detect)
    opts = {"body_key": "message"}
    assert await h._resolved_response_field("http://t/chat", opts) == opts


def test_parse_known_probes_skips_probes_label():
    # a stray 'probes.<Class>' token is the label, not a module — skipped
    classes, modules = h._parse_known_probes("noise probes.Skip real.Class")
    assert "real" in modules and "probes" not in modules
