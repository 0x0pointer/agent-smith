"""Tests for the AI Red Team dashboard data layer (core.ai_redteam + /api/ai-redteam)."""
import pathlib

import pytest
from fastapi.testclient import TestClient

from core import ai_redteam as ar
from core.api_server import app

client = TestClient(app)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(ar, "_FILE", tmp_path / "ai_redteam.json")
    return ar


def test_empty_store_shape(store):
    doc = store.get()
    assert set(doc) >= {"garak", "filter", "calibration", "attacks"}
    assert doc["garak"] == []
    assert doc["attacks"] == []


def test_record_garak_parses_0_15_rate(store):
    raw = ("junk\n=== GARAK REPORT JSONL ===\n"
           '{"entry_type":"eval","probe":"encoding.InjectBase64","detector":"encoding.DecodeMatch",'
           '"passed":203,"fails":53,"total_evaluated":256}\n'
           '{"entry_type":"attempt","seq":1}')   # attempt lines must be ignored
    store.record_garak_from_raw(raw, "http://t/chat")
    g = store.get()["garak"]
    assert len(g) == 1
    assert g[0]["fails"] == 53
    assert g[0]["total"] == 256
    assert g[0]["attack_success_rate"] == round(53 / 256, 4)


def test_record_garak_ignores_empty(store):
    store.record_garak_from_raw("no report here", "x")
    assert store.get()["garak"] == []


def test_record_filter_calibration_attack(store):
    store.record_filter_probe({"plaintext_blocked": True, "bypass": ["base64"],
                               "detail": {"direct": False, "base64": True}}, "http://t")
    store.record_calibration({"calibrated": True, "summary": "4/4 passed"})
    store.record_attack({"jailbroken": True, "attempts": 12,
                         "best": {"technique": "roleplay", "transform": "base64"},
                         "reproducibility": {"k": 6, "n": 6, "rate": 1.0},
                         "transcript": [{"phase": 1, "technique": "direct", "score": 0.3}]},
                        "leak secret", "http://t")
    doc = store.get()
    assert doc["filter"]["bypass"] == ["base64"]
    assert doc["calibration"]["calibrated"] is True
    assert doc["attacks"][0]["jailbroken"]
    assert doc["attacks"][0]["reproducibility"]["k"] == 6


def test_reset(store):
    store.record_calibration({"calibrated": True})
    store.reset()
    assert store.get()["calibration"] is None


def test_attacks_capped(store):
    for i in range(60):
        store.record_attack({"jailbroken": False, "attempts": 1, "goal": str(i)}, str(i), "x")
    assert len(store.get()["attacks"]) <= 50


# ── the /api/ai-redteam route ───────────────────────────────────────────────

def test_api_ai_redteam_route():
    r = client.get("/api/ai-redteam")
    assert r.status_code == 200
    data = r.json()
    assert set(data) >= {"garak", "filter", "calibration", "attacks"}


def test_dashboard_has_ai_redteam_tab():
    """The shell must include the AI Red Team tab partial + nav button + script."""
    html = client.get("/").text
    assert "tab-btn-ai-redteam" in html
    assert "switchTab('ai-redteam')" in html
    assert "/static/js/ai-redteam.js" in html
    # the partial must be included (its container div id)
    assert 'id="tab-ai-redteam"' in html


def test_parse_garak_eval_fallbacks(store):
    # 'total' (legacy, not total_evaluated) + fails inferred from passed
    raw = ('=== GARAK REPORT JSONL ===\n'
           '{"entry_type":"eval","probe":"p","detector":"d","passed":8,"total":10}\n')
    store.record_garak_from_raw(raw, "t")
    g = store.get()["garak"][-1]
    assert g["total"] == 10
    assert g["fails"] == 2
    assert g["attack_success_rate"] == round(2 / 10, 4)


def test_toolchain_status_shape_and_cache(store):
    store._HEALTH_CACHE.update(ts=0, data=None)
    s = store.toolchain_status()
    assert "ready" in s
    assert isinstance(s["components"], list) and s["components"]
    assert any(c["name"].startswith("transform") for c in s["components"])
    assert any(c["name"].startswith("redteam") for c in s["components"])
    # a second call within the TTL returns the cached object
    assert store.toolchain_status() == s


def test_taxonomy_overview_shape(store):
    store._TAX_CACHE.update(data=None, done=False)
    d = store.taxonomy_overview()
    assert d["total"] == 172
    assert set(d["pillars"]) == {"intents", "techniques", "evasions", "inputs"}
    ex = d["engine"]["executable"]
    assert ex["tuned"] == 13
    assert ex["unique"] >= 70
    assert d["license"].startswith("CC BY")


def test_record_attack_trims_transcript(store):
    turns = [{"phase": 1, "technique": "direct", "score": 0.1} for _ in range(30)]
    store.record_attack({"jailbroken": False, "attempts": 30, "best": {}, "transcript": turns},
                        "goal", "http://t")
    assert len(store.get()["attacks"][-1]["transcript"]) == 12


def test_store_is_failsoft_on_io_errors(store, tmp_path):
    # write to a path whose parent doesn't exist -> write raises -> swallowed
    store._FILE = tmp_path / "missing" / "deep" / "ai.json"
    store.record_calibration({"calibrated": True})     # must not raise
    # read from a directory path -> read raises -> fail-soft empty doc
    d = tmp_path / "adir"; d.mkdir()
    store._FILE = d
    assert store.get()["garak"] == []
