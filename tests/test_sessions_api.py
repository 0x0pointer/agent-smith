"""Tests for GET /api/sessions — the dashboard Sessions index (issue #187).

Redirects core.paths.SMITH_EVENTS_DIR and SESSION_FILE (both read at call time),
mirroring test_session_log_api.py. Covers enumeration, origin badging (operator vs
watchdog), status derivation (live current / terminal-snapshot complete / inactive),
and the findings count.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

import core.paths as paths
from core.api_server import app

client = TestClient(app)


@pytest.fixture
def events_dir(tmp_path, monkeypatch):
    d = tmp_path / "smith-events"
    monkeypatch.setattr(paths, "SMITH_EVENTS_DIR", d)
    monkeypatch.setattr(paths, "SESSION_FILE", tmp_path / "session.json")
    return d


def _session(events_dir, sid, *, target="t", origin=None, started="2026-01-01T00:00:00+00:00",
             mtime=None, findings=None, finding_events=0):
    """Create a session's stream + meta.json (+ optional terminal findings snapshot)."""
    events_dir.mkdir(parents=True, exist_ok=True)
    evs = [{"event_id": f"E{i}", "engagement_id": sid, "event_type": "finding",
            "sequence": i, "finding": {"title": f"f{i}"}} for i in range(finding_events)]
    p = events_dir / f"{sid}.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in evs) + "\n", encoding="utf-8")
    if mtime is not None:
        os.utime(p, (mtime, mtime))
    d = events_dir / sid
    d.mkdir(parents=True, exist_ok=True)
    meta = {"id": sid, "target": target, "started": started}
    if origin is not None:
        meta["origin"] = origin
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    if findings is not None:
        (d / "findings.json").write_text(json.dumps({"findings": [{"title": f"f{i}"} for i in range(findings)]}),
                                         encoding="utf-8")
    return p


def _set_current(sid, status):
    (paths.SESSION_FILE).write_text(json.dumps({"id": sid, "status": status}), encoding="utf-8")


def test_empty_when_no_dir(events_dir):
    r = client.get("/api/sessions")
    assert r.status_code == 200
    body = r.json()
    assert body["sessions"] == [] and body["count"] == 0 and body["current"] is None


def test_lists_sessions_newest_first(events_dir):
    _session(events_dir, "old", target="a.com", mtime=1000)
    _session(events_dir, "new", target="b.com", mtime=2000)
    rows = client.get("/api/sessions").json()["sessions"]
    assert [r["id"] for r in rows] == ["new", "old"]
    assert rows[0]["target"] == "b.com"


def test_origin_badging(events_dir):
    _session(events_dir, "op", origin=None)          # default → operator
    _session(events_dir, "wd", origin="watchdog")
    by_id = {r["id"]: r for r in client.get("/api/sessions").json()["sessions"]}
    assert by_id["op"]["origin"] == "operator" and by_id["op"]["auto_started"] is False
    assert by_id["wd"]["origin"] == "watchdog" and by_id["wd"]["auto_started"] is True


def test_status_current_vs_complete_vs_inactive(events_dir):
    _session(events_dir, "cur")                       # will be the live current session
    _session(events_dir, "done", findings=3)          # has terminal findings snapshot
    _session(events_dir, "old")                        # neither
    _set_current("cur", "running")
    body = client.get("/api/sessions").json()
    by_id = {r["id"]: r for r in body["sessions"]}
    assert body["current"] == "cur"
    assert by_id["cur"]["status"] == "running"
    assert by_id["done"]["status"] == "complete"
    assert by_id["old"]["status"] == "inactive"


def test_findings_count_from_snapshot_and_events(events_dir):
    _session(events_dir, "snap", findings=5)          # snapshot wins
    _session(events_dir, "stream", finding_events=2)  # no snapshot → count events
    by_id = {r["id"]: r for r in client.get("/api/sessions").json()["sessions"]}
    assert by_id["snap"]["findings"] == 5
    assert by_id["stream"]["findings"] == 2
