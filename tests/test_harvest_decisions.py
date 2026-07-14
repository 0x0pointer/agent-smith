"""Passive decision harvester (training-data/eventstore/harvest_decisions.py): correlates transcript
reasoning to emitted `action` events, emits schema-valid `decision`s that `explains` (not caused_by)
the action, keeps Smith's words verbatim, and leaves un-reasoned / drifted actions unattributed."""
import importlib.util
import json
import pathlib

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("harvest_decisions", _ROOT / "training-data" / "eventstore" / "harvest_decisions.py")
hd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hd)

_SCHEMAS = _ROOT / "training-data" / "schemas"
_RES = [(json.loads(f.read_text())["$id"], Resource.from_contents(json.loads(f.read_text())))
        for f in sorted(_SCHEMAS.glob("*.json"))]
_REG = Registry().with_resources(_RES)
_DECISION = next(r.contents for i, r in _RES if i == "decision-event.schema.json")


def _tool_use(name, inp):
    return {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "name": name, "input": inp}]}}


def _reasoning(text, thinking=False):
    block = {"type": "thinking", "thinking": text} if thinking else {"type": "text", "text": text}
    return {"type": "assistant", "timestamp": "2026-07-14T12:00:00+00:00",
            "message": {"role": "assistant", "content": [block]}}


def _action(seq, eid, tool, corr=None):
    ev = {"event_id": eid, "engagement_id": "eng-h", "event_type": "action", "sequence": seq,
          "action": {"tool": tool, "operation": "call", "exact_action_hash": "sha256:" + "0" * 64,
                     "semantic_action_family": {"target_entity": "t", "operation_class": tool, "payload_family": "x"},
                     "safety_class": "read_only"}}
    if corr:
        ev["correlation_id"] = corr
    return ev


def _write(p, rows):
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_harvest_correlates_schema_valid_and_honest(tmp_path):
    transcript = [
        _reasoning("The root page leaked a Werkzeug console; I'll probe /console for RCE.", thinking=True),
        _tool_use("mcp__pentest-agent__http", {"method": "GET", "url": "http://x/console"}),   # -> http_request, reasoned
        {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "content": "200"}]}},
        _reasoning("Now sweep for known CVEs."),
        _tool_use("mcp__pentest-agent__scan", {"tool": "nuclei"}),                              # -> nuclei, reasoned
        _tool_use("mcp__pentest-agent__report", {"action": "finding"}),                         # not wrap-routed; resets buffer
        _tool_use("mcp__pentest-agent__kali", {"command": "id"}),                               # -> kali, NO reasoning left
    ]
    events = [
        _action(1, "01AAAAAAAAAAAAAAAAAAAAAAAA", "http_request", corr="c1"),
        {"event_type": "result", "sequence": 2, "event_id": "r1", "engagement_id": "eng-h"},
        _action(3, "01BBBBBBBBBBBBBBBBBBBBBBBB", "nuclei"),
        _action(5, "01CCCCCCCCCCCCCCCCCCCCCCCC", "kali"),
    ]
    tpath, epath = tmp_path / "t.jsonl", tmp_path / "eng-h.jsonl"
    _write(tpath, transcript)
    _write(epath, events)

    stats = hd.harvest(tpath, epath, tmp_path / "out.jsonl")
    assert stats["actions"] == 3
    assert stats["harvested"] == 2                    # http_request + nuclei had reasoning
    assert stats["unattributed_no_reasoning"] == 1    # kali's reasoning was consumed by the report call

    decisions = [json.loads(x) for x in (tmp_path / "out.jsonl").read_text().splitlines() if x.strip()]
    assert len(decisions) == 2
    for d in decisions:
        assert not list(Draft202012Validator(_DECISION, registry=_REG).iter_errors(d)), d
        assert d["event_type"] == "decision"
        assert "caused_by" not in d                                   # NOT a causal parent
        assert len(d["explains"]) == 1                                # reference edge to the action
        assert d["decision"]["capture_method"] == "transcript_harvest"
        assert d["decision"]["confidence"]["capture_mode"] == "not_captured"   # structure not parsed
        assert d["sequence"] > 5                                       # late-arriving -> after the stream
    first = decisions[0]
    assert first["explains"] == ["01AAAAAAAAAAAAAAAAAAAAAAAA"]
    assert first["correlation_id"] == "c1"
    assert "Werkzeug console" in first["decision"]["explanation"]      # Smith's ACTUAL words, verbatim
    assert first["decision"]["chosen_tool"] == "http_request"


def test_harvest_skips_on_tool_drift(tmp_path):
    # transcript's first wrap call is http, but the first action is nuclei -> mismatch -> unattributed
    transcript = [_reasoning("reasoning"), _tool_use("mcp__pentest-agent__http", {"method": "GET"})]
    events = [_action(1, "01DDDDDDDDDDDDDDDDDDDDDDDD", "nuclei")]
    tpath, epath = tmp_path / "t.jsonl", tmp_path / "eng.jsonl"
    _write(tpath, transcript)
    _write(epath, events)
    stats = hd.harvest(tpath, epath, tmp_path / "out.jsonl")
    assert stats["harvested"] == 0 and stats["drift"] == 1
    assert (tmp_path / "out.jsonl").read_text().strip() == ""


def test_inner_tool_mapping():
    assert hd._inner_tool("mcp__pentest-agent__scan", {"tool": "httpx"}) == "httpx"
    assert hd._inner_tool("pentest-agent_http", {}) == "http_request"
    assert hd._inner_tool("kali", {}) == "kali"
    assert hd._inner_tool("mcp__pentest-agent__session", {"action": "start"}) is None   # not wrap-routed
    assert hd._inner_tool("mcp__pentest-agent__report", {"action": "finding"}) is None
