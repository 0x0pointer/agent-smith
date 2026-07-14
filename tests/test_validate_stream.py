"""Freeze-acceptance validator (training-data/eventstore/validate_stream.py): a well-formed real
stream passes; DAG violations, broken result linkage, and secret leaks fail."""
import importlib.util
import json
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("validate_stream", _ROOT / "training-data" / "eventstore" / "validate_stream.py")
vs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vs)

H = "sha256:" + "0" * 64
A_ID, R_ID = "01AAAAAAAAAAAAAAAAAAAAAAAA", "01BBBBBBBBBBBBBBBBBBBBBBBB"


def _env(eid, etype, seq, **extra):
    e = {"event_id": eid, "engagement_id": "e", "event_type": etype, "sequence": seq,
         "occurred_at": "2026-07-14T12:00:00+00:00", "recorded_at": "2026-07-14T12:00:00+00:00",
         "schema_version": "smith-event/1.0"}
    e.update(extra)
    return e


def _action(seq=1, eid=A_ID):
    return {**_env(eid, "action", seq),
            "action": {"tool": "httpx", "operation": "call", "exact_action_hash": H,
                       "semantic_action_family": {"target_entity": "t", "operation_class": "httpx", "payload_family": "x"},
                       "safety_class": "read_only"}}


def _result(seq=2, eid=R_ID, caused_by=(A_ID,)):
    return {**_env(eid, "result", seq, caused_by=list(caused_by)),
            "result": {"observed": {"execution_status": "ok", "result_class": "ok"}}}


def _write(p, rows):
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_good_stream_passes(tmp_path):
    p = tmp_path / "s.jsonl"
    _write(p, [_action(), _result()])
    res = vs.validate_stream(p, tmp_path / "none.jsonl")
    assert res["ok"], res["errors"]
    assert res["census"]["action"] == 1 and res["census"]["result"] == 1


def test_missing_causal_parent_fails(tmp_path):
    p = tmp_path / "s.jsonl"
    _write(p, [_result(seq=1, caused_by=("01ZZZZZZZZZZZZZZZZZZZZZZZZ",))])   # parent doesn't exist
    res = vs.validate_stream(p, tmp_path / "none.jsonl")
    assert not res["ok"]
    assert any("missing" in e or "caused_by" in e for e in res["errors"])


def test_parent_sequence_not_lower_fails(tmp_path):
    p = tmp_path / "s.jsonl"
    # result at seq 1 caused_by an action at seq 2 -> parent seq not lower (DAG violation)
    _write(p, [_result(seq=1), _action(seq=2)])
    res = vs.validate_stream(p, tmp_path / "none.jsonl")
    assert not res["ok"]
    assert any("not lower" in e for e in res["errors"])


def test_leak_fails(tmp_path):
    p = tmp_path / "s.jsonl"
    a = _action()
    a["action"]["params"] = {"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaa.bbbb"}
    _write(p, [a, _result()])
    res = vs.validate_stream(p, tmp_path / "none.jsonl")
    assert not res["ok"]
    assert any("LEAK" in e for e in res["errors"])


def test_harvested_decision_explains_must_resolve(tmp_path):
    p, dp = tmp_path / "s.jsonl", tmp_path / "s.decisions.jsonl"
    _write(p, [_action(), _result()])
    nc = {"value": None, "capture_mode": "not_captured"}
    bad_dec = {**_env("01CCCCCCCCCCCCCCCCCCCCCCCC", "decision", 99, explains=["01NOPE0000000000000000000A"]),
               "decision": {"goal": "", "chosen_tool": "httpx", "operation": "call", "confidence": nc,
                            "alternatives_considered": nc, "expected_signals": nc, "stop_condition": nc,
                            "provenance": {"proposal_source": "model", "teacher_origin": "open_weight"}}}
    _write(dp, [bad_dec])
    res = vs.validate_stream(p, dp)
    assert not res["ok"]
    assert any("explains does not resolve" in e for e in res["errors"])
