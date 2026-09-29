"""Tests for GET /api/session-log — the per-session reasoning-log read API (issue #186).

Uses FastAPI's TestClient. The events dir is redirected via core.paths.SMITH_EVENTS_DIR
(the route reads it at call time), mirroring how smith_events keeps its dir monkeypatchable.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

import core.paths as paths
from core.api_server import app

client = TestClient(app)


def _write_stream(events_dir, sid, events, mtime=None, meta=None):
    events_dir.mkdir(parents=True, exist_ok=True)
    p = events_dir / f"{sid}.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    if mtime is not None:
        os.utime(p, (mtime, mtime))
    if meta is not None:
        d = events_dir / sid
        d.mkdir(parents=True, exist_ok=True)
        (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return p


@pytest.fixture
def events_dir(tmp_path, monkeypatch):
    d = tmp_path / "smith-events"
    monkeypatch.setattr(paths, "SMITH_EVENTS_DIR", d)
    return d


def _note(seq, msg):
    return {"event_id": f"E{seq}", "engagement_id": "x", "event_type": "note",
            "sequence": seq, "occurred_at": "2026-01-01T00:00:00+00:00",
            "note": {"message": msg}}


def _action(seq, tool):
    return {"event_id": f"E{seq}", "engagement_id": "x", "event_type": "action",
            "sequence": seq, "occurred_at": "2026-01-01T00:00:00+00:00",
            "action": {"tool": tool, "operation": "call"}}


def test_empty_when_no_dir(events_dir):
    r = client.get("/api/session-log")
    assert r.status_code == 200
    body = r.json()
    assert body["sessions"] == [] and body["events"] == [] and body["session"] is None


def test_lists_sessions_and_defaults_to_newest_by_mtime(events_dir):
    _write_stream(events_dir, "aaa", [_note(1, "older")], mtime=1000,
                  meta={"id": "aaa", "target": "http://a.test", "started": "2026-01-01T00:00:00+00:00"})
    _write_stream(events_dir, "bbb", [_note(1, "newer note"), _action(2, "nmap")], mtime=2000)

    r = client.get("/api/session-log")
    body = r.json()
    assert body["session"] == "bbb"                      # newest by mtime, not filename
    ids = {s["id"] for s in body["sessions"]}
    assert ids == {"aaa", "bbb"}
    # nested payload surfaced under "payload"
    types = [e["event_type"] for e in body["events"]]
    assert types == ["note", "action"]
    assert body["events"][0]["payload"]["message"] == "newer note"


def test_meta_enrichment_and_fallback(events_dir):
    _write_stream(events_dir, "aaa", [_note(1, "x")], mtime=1000,
                  meta={"id": "aaa", "target": "http://a.test", "started": "2026-01-01T00:00:00+00:00"})
    _write_stream(events_dir, "bbb", [_note(1, "y")], mtime=2000)   # no meta subdir
    sessions = {s["id"]: s for s in client.get("/api/session-log").json()["sessions"]}
    assert sessions["aaa"]["target"] == "http://a.test"
    assert sessions["bbb"]["target"] is None                        # graceful fallback, no crash


def test_select_specific_session(events_dir):
    _write_stream(events_dir, "aaa", [_note(1, "hello aaa")], mtime=1000)
    _write_stream(events_dir, "bbb", [_note(1, "hello bbb")], mtime=2000)
    body = client.get("/api/session-log?session=aaa").json()
    assert body["session"] == "aaa"
    assert body["events"][0]["payload"]["message"] == "hello aaa"


def test_invalid_or_traversal_session_rejected(events_dir):
    _write_stream(events_dir, "aaa", [_note(1, "x")], mtime=1000)
    body = client.get("/api/session-log?session=../../etc/passwd").json()
    assert body.get("error") == "invalid session"
    assert body["events"] == [] and body["session"] is None
    # the real sessions are still listed so the UI can recover
    assert {s["id"] for s in body["sessions"]} == {"aaa"}


def test_malformed_final_line_does_not_500(events_dir):
    events_dir.mkdir(parents=True, exist_ok=True)
    p = events_dir / "aaa.jsonl"
    p.write_text(json.dumps(_note(1, "good")) + "\n" + '{"event_type": "note", "sequ', encoding="utf-8")
    r = client.get("/api/session-log?session=aaa")
    assert r.status_code == 200
    body = r.json()
    assert len(body["events"]) == 1                                 # bad line skipped, good one kept
    assert body["events"][0]["payload"]["message"] == "good"


def test_endpoint_is_mounted():
    # Guards the routes/__init__.py registration — a missing import = silent 404.
    assert client.get("/api/session-log").status_code != 404


def test_dashboard_has_session_log_tab():
    # Catches a forgotten nav button / {% include %} / <script> (and a missing Jinja partial).
    html = client.get("/").text
    assert "tab-btn-session-log" in html
    assert "switchTab('session-log')" in html
    assert "/static/js/session-log.js" in html
    assert 'id="tab-session-log"' in html
