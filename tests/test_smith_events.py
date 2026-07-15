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
_SCHEMA_FOR = {"action": "action-event.schema.json", "result": "result-event.schema.json",
               "decision": "decision-event.schema.json", "finding": "finding-event.schema.json",
               "coverage_transition": "coverage-transition-event.schema.json"}


class FakeResult:
    def __init__(self, evidence=None, anomalies=None):
        self.evidence = evidence or {}
        self.anomalies = anomalies or []


@pytest.fixture
def emit_env(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "_EVENTS_DIR", tmp_path)
    monkeypatch.setattr(se, "_seq", {})
    monkeypatch.setattr(se, "_current_decision", {})
    import core.session as cs
    monkeypatch.setattr(cs, "get", lambda: {"id": "eng-test", "model_profile": "full"})
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


def test_emit_decision_schema_valid_with_honest_capture_mode(emit_env):
    did = se.emit_decision({"goal": "confirm SQLi on email param", "chosen_tool": "http_request",
                            "operation": "request", "technique": "CWE-89", "confidence": 0.6,
                            "alternatives_considered": ["blind", "time-based"]})
    assert did
    d = _events(emit_env)[0]
    _validate(d)
    assert d["event_type"] == "decision"
    # provided fields -> pre_decision_generated; absent fields -> not_captured (never fabricated)
    assert d["decision"]["confidence"] == {"value": 0.6, "capture_mode": "pre_decision_generated", "actor": "model"}
    assert d["decision"]["expected_signals"]["capture_mode"] == "not_captured"
    assert d["decision"]["stop_condition"]["capture_mode"] == "not_captured"
    assert d["decision"]["provenance"]["teacher_origin"] == "open_weight"
    assert d["decision"]["provenance"]["proposal_source"] == "model:full"


def test_action_links_caused_by_current_decision(emit_env):
    did = se.emit_decision({"goal": "g", "chosen_tool": "http_request", "operation": "request"})
    se.emit_tool_call("http_request", {"method": "GET", "url": "http://x"}, FakeResult())
    d, a, r = _events(emit_env)
    assert d["event_id"] == did and (d["sequence"], a["sequence"], r["sequence"]) == (1, 2, 3)
    assert a["caused_by"] == [did] and a["correlation_id"] == did      # action executes the decision
    assert r["caused_by"] == [a["event_id"]] and r["correlation_id"] == did  # result under same decision
    for e in (d, a, r):
        _validate(e) if e["event_type"] in _SCHEMA_FOR else None


def test_action_without_decision_has_no_causal_link(emit_env):
    se.emit_tool_call("httpx", {"target": "x"}, FakeResult())   # no decision recorded first
    a = _events(emit_env)[0]
    assert "caused_by" not in a and "correlation_id" not in a   # unattributed action is honest, not fabricated


def test_emit_decision_no_session_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "_EVENTS_DIR", tmp_path)
    monkeypatch.setattr(se, "_seq", {})
    monkeypatch.setattr(se, "_current_decision", {})
    import core.session as cs
    monkeypatch.setattr(cs, "get", lambda: None)
    assert se.emit_decision({"goal": "g", "chosen_tool": "x"}) is None
    assert not list(tmp_path.glob("*.jsonl"))


def test_emit_finding_schema_valid_and_linked_to_decision(emit_env):
    did = se.emit_decision({"goal": "g", "chosen_tool": "http_request", "operation": "request"})
    se.emit_finding({"title": "SQLi on login", "severity": "CRITICAL", "target": "http://x/login",
                     "technique": "CWE-89"}, "F-123", "kali_99_abc")
    d, f = _events(emit_env)
    _validate(f)
    assert f["event_type"] == "finding"
    assert f["finding"]["finding_id"] == "F-123"
    assert f["finding"]["severity"] == "critical"          # coerced lowercase
    assert f["finding"]["proof_artifact_id"] == "kali_99_abc"
    assert f["caused_by"] == [did] and f["correlation_id"] == did   # finding under the decision


def test_emit_finding_bad_severity_coerced_and_no_id_dropped(emit_env):
    se.emit_finding({"title": "x", "severity": "BOGUS", "target": "t"}, "F-1")
    assert _events(emit_env)[0]["finding"]["severity"] == "info"    # unknown severity -> info
    se.emit_finding({"title": "y", "severity": "high", "target": "t"}, "")   # no finding_id
    assert len(_events(emit_env)) == 1                              # dropped, not emitted


def test_emit_coverage_transition_schema_valid(emit_env):
    se.emit_coverage_transition({"cell_id": "cell-abc", "status": "vulnerable", "finding_id": "F-1",
                                 "injection_type": "sqli", "param_name": "email"})
    c = _events(emit_env)[0]
    _validate(c)
    assert c["event_type"] == "coverage_transition"
    assert c["coverage_transition"]["status"] == "vulnerable"
    assert c["coverage_transition"]["finding_id"] == "F-1"


def test_coverage_transition_invalid_dropped(emit_env):
    se.emit_coverage_transition({"cell_id": "c", "status": "bogus"})   # bad status
    se.emit_coverage_transition({"status": "tested_clean"})            # missing cell_id
    assert not _events(emit_env)                                       # both dropped, never emitted


def test_emit_tool_call_copies_artifact_and_links_it(emit_env, monkeypatch, tmp_path):
    import mcp_server.scan_engine.artifacts as arts
    src_dir = tmp_path / "src_artifacts"
    src_dir.mkdir()
    (src_dir / "http_req_1.txt").write_text("HTTP/1.1 200 OK\r\n\r\n{\"balance\": 1}")
    monkeypatch.setattr(arts, "_ARTIFACTS_DIR", src_dir)

    se.emit_tool_call("http_request", {"method": "GET", "url": "http://x"}, FakeResult(), artifact_id="http_req_1")

    r = _events(emit_env)[1]
    _validate(r)
    assert r["result"]["artifact_id"] == "http_req_1"                      # linked in the event
    copied = emit_env / "eng-test" / "http_req_1.txt"
    assert copied.exists() and "200 OK" in copied.read_text()             # durable copy survives the wipe
    meta = json.loads((emit_env / "eng-test" / "meta.json").read_text())  # provenance snapshot
    assert meta["id"] == "eng-test" and meta["model_profile"] == "full"


def test_emit_tool_call_fail_soft_when_artifact_missing(emit_env, monkeypatch, tmp_path):
    import mcp_server.scan_engine.artifacts as arts
    monkeypatch.setattr(arts, "_ARTIFACTS_DIR", tmp_path / "nope")   # source doesn't exist
    se.emit_tool_call("httpx", {"target": "x"}, FakeResult(), artifact_id="missing_123")
    r = _events(emit_env)[1]
    assert r["result"]["artifact_id"] == "missing_123"              # still referenced (event never lies about the id)
    assert not (emit_env / "eng-test" / "missing_123.txt").exists()  # nothing copied; no crash


def test_emit_tool_call_no_artifact_id_omits_field(emit_env):
    se.emit_tool_call("nmap", {"target": "h"}, FakeResult())        # no artifact_id
    assert "artifact_id" not in _events(emit_env)[1]["result"]
