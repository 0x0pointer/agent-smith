"""Runtime smith-event emitter (mcp_server/scan_engine/smith_events.py): emitted events validate
against training-data/schemas/, sequence/causality hold, kali commands are redacted, and the whole
path is fail-soft + gated."""
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

import mcp_server.scan_engine.smith_events as se

_SCHEMAS = pathlib.Path(__file__).resolve().parents[1] / "training-data" / "schemas"
_RES = [(json.loads(f.read_text())["$id"], Resource.from_contents(json.loads(f.read_text())))
        for f in sorted(_SCHEMAS.glob("*.json"))]
_REG = Registry().with_resources(_RES)
_BY = {i: r.contents for i, r in _RES}
_SCHEMA_FOR = {"action": "action-event.schema.json", "result": "result-event.schema.json"}


class FakeResult:
    def __init__(self, evidence=None, anomalies=None):
        self.evidence = evidence or {}
        self.anomalies = anomalies or []


@pytest.fixture
def emit_env(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "_EVENTS_DIR", tmp_path)
    monkeypatch.setattr(se, "_seq", {})
    import core.session as cs
    monkeypatch.setattr(cs, "get", lambda: {"id": "eng-test"})
    return tmp_path


def _events(tmp_path, eng="eng-test"):
    p = tmp_path / f"{eng}.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def _validate(ev):
    errs = [e.message for e in Draft202012Validator(_BY[_SCHEMA_FOR[ev["event_type"]]], registry=_REG).iter_errors(ev)]
    assert not errs, f"{ev['event_type']}: {errs}"


def test_emits_schema_valid_action_result_pair(emit_env):
    se.emit_tool_call("httpx", {"target": "http://x.test"}, FakeResult())
    evs = _events(emit_env)
    assert [e["event_type"] for e in evs] == ["action", "result"]
    for e in evs:
        _validate(e)
    a, r = evs
    assert r["caused_by"] == [a["event_id"]]                 # result caused_by the action
    assert (a["sequence"], r["sequence"]) == (1, 2)          # monotonic
    assert a["action"]["safety_class"] == "read_only"        # httpx only reads
    assert a["action"]["exact_action_hash"].startswith("sha256:")


def test_sequence_monotonic_across_calls(emit_env):
    for _ in range(3):
        se.emit_tool_call("nmap", {"target": "h"}, FakeResult())
    assert [e["sequence"] for e in _events(emit_env)] == [1, 2, 3, 4, 5, 6]


def test_kali_command_redacted_and_state_mutating(emit_env):
    se.emit_tool_call("kali", {"command": "curl -H 'Authorization: Bearer eyJhbGciOiJodHRwOi8vZXhhbXBsZQ' http://x"}, FakeResult())
    a = _events(emit_env)[0]
    assert "eyJhbGc" not in json.dumps(a)                    # JWT redacted out of params
    assert a["action"]["safety_class"] == "state_mutating"
    assert a["action"]["operation"] == "exec"


def test_error_status_and_result_class(emit_env):
    se.emit_tool_call("http_request", {"method": "GET", "url": "http://x"}, FakeResult(evidence={"error": "boom"}))
    r = _events(emit_env)[1]
    assert r["result"]["observed"] == {"execution_status": "error", "result_class": "error"}


def test_no_active_session_emits_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "_EVENTS_DIR", tmp_path)
    monkeypatch.setattr(se, "_seq", {})
    import core.session as cs
    monkeypatch.setattr(cs, "get", lambda: None)
    se.emit_tool_call("httpx", {"target": "x"}, FakeResult())
    assert not list(tmp_path.glob("*.jsonl"))


def test_fail_soft_on_malformed_result(emit_env):
    se.emit_tool_call("httpx", {"target": "x"}, object())    # no .evidence attr -> must not raise
    assert _events(emit_env)                                  # still emitted (evidence defaults to {})


def test_disabled_via_env(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "_EVENTS_DIR", tmp_path)
    monkeypatch.setattr(se, "_seq", {})
    monkeypatch.setenv("SMITH_EVENTS_DISABLED", "1")
    import core.session as cs
    monkeypatch.setattr(cs, "get", lambda: {"id": "e"})
    se.emit_tool_call("httpx", {"target": "x"}, FakeResult())
    assert not list(tmp_path.glob("*.jsonl"))


def test_ulid_matches_schema_pattern(emit_env):
    se.emit_tool_call("nuclei", {"target": "x"}, FakeResult())
    import re
    for e in _events(emit_env):
        assert re.fullmatch(r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}", e["event_id"])
