"""Unit tests for the garak handler's response_field auto-detect + probe
validation (mcp_server.scan_tools.handlers_ai). No Docker / network invoked."""
import pytest

import mcp_server.scan_tools.handlers_ai as h


@pytest.fixture(autouse=True)
def _isolate_coverage(tmp_path, monkeypatch):
    """Point the coverage matrix at an empty tmp path so autodetect tests don't
    read the machine's live scan matrix (which could seed real /chat keys)."""
    import core.coverage as cov
    monkeypatch.setattr(cov, "COVERAGE_FILE", tmp_path / "coverage_matrix.json")


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


# ── Layer 2: seed candidate keys from what the model registered in coverage ───

def test_ordered_candidates_dedups_and_orders():
    assert h._ordered_candidates(["a"], ["b", "a"], [], ["c", None, "b"]) == ["a", "b", "c"]
    assert h._ordered_candidates(None, [""], ["x"]) == ["x"]


@pytest.mark.parametrize("params,expect", [
    # only the prompt-ish param, not temperature/stream/_endpoint
    ([{"name": "temperature", "type": "body", "value_hint": "float"},
      {"name": "prompt_text_v2", "type": "body", "value_hint": "string"},
      {"name": "_endpoint", "type": "endpoint"}], ["prompt_text_v2"]),
    ([{"name": "q7", "type": "body"}], ["q7"]),          # a sole opaque key IS the input
    ([{"name": "a"}, {"name": "b"}], []),               # neither texty and >1 param
    ([], []),
    ([{"name": "note", "type": "body", "value_hint": "the user message"}], ["note"]),  # hint texty
])
def test_texty_param_names(params, expect):
    assert h._texty_param_names(params) == expect


def test_keys_from_coverage_matches_path(monkeypatch):
    import core.coverage as cov
    fake = {"endpoints": [
        {"path": "http://t/chat", "method": "POST",
         "params": [{"name": "prompt_text_v2", "type": "body", "value_hint": "string"}]},
        {"path": "/other", "method": "POST",
         "params": [{"name": "message", "type": "body"}]},
    ]}
    monkeypatch.setattr(cov, "_load", lambda: fake)
    assert h._keys_from_coverage("http://t/chat") == ["prompt_text_v2"]
    assert h._keys_from_coverage("http://t/other") == ["message"]


def test_keys_from_coverage_failsoft(monkeypatch):
    import core.coverage as cov

    def _boom():
        raise RuntimeError("no matrix")
    monkeypatch.setattr(cov, "_load", _boom)
    assert h._keys_from_coverage("http://t/chat") == []


@pytest.mark.asyncio
async def test_autodetect_uses_coverage_recorded_key(monkeypatch):
    """A CUSTOM input key not in _INPUT_KEYS and not named by the error is still
    found because the model recorded it in the coverage matrix during recon."""
    import aiohttp

    def _handler(body):
        if body.get("prompt_text_v2"):
            return 200, '{"response": "Hello!"}'
        return 400, '{"error": "bad request"}'   # opaque — names no field

    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: _MockSession(_handler))
    monkeypatch.setattr(h, "_keys_from_coverage", lambda t: ["prompt_text_v2"])
    body_key, field, diag = await h._autodetect_rest_shape("http://t/chat", {})
    assert body_key == "prompt_text_v2"
    assert field == "$.response"
