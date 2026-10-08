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


def test_record_garak_upserts_not_duplicates(store):
    # streaming calls this repeatedly with a growing partial for the SAME run —
    # the row must be refined in place, never duplicated.
    marker = "=== GARAK REPORT JSONL ==="
    e1 = ('{"entry_type":"eval","probe":"dan.AntiDAN","detector":"d","passed":2,"total_evaluated":10}')
    e2 = ('{"entry_type":"eval","probe":"dan.AntiDAN","detector":"d","passed":4,"total_evaluated":20}')
    store.record_garak_from_raw(f"{marker}\n{e1}", "http://t/chat")
    store.record_garak_from_raw(f"{marker}\n{e2}", "http://t/chat")   # same probe+detector+target
    rows = store.get()["garak"]
    assert len(rows) == 1                       # upserted, not appended
    assert rows[0]["total"] == 20               # refined to the latest numbers
    # a DIFFERENT probe (or target) is a distinct row
    e3 = ('{"entry_type":"eval","probe":"encoding.InjectBase64","detector":"d","passed":1,"total_evaluated":5}')
    store.record_garak_from_raw(f"{marker}\n{e3}", "http://t/chat")
    assert len(store.get()["garak"]) == 2


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
    assert isinstance(s["components"], list)
    assert s["components"]
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


# ── MCP-tools readiness: survives a dashboard "Clear logs" (live registry) ────
# NOTE: conftest shims @mcp.tool() to a no-op, so the live registry is empty under
# pytest — tests mock _tool_manager.list_tools() to exercise the live-registry path
# the real server hits.
_REQUIRED_MCP = {"scan", "transform", "redteam", "http", "report", "session"}


class _FakeTool:
    def __init__(self, name):
        self.name = name


def _mock_live_tools(monkeypatch, names):
    import mcp_server._app as _app
    monkeypatch.setattr(_app.mcp._tool_manager, "list_tools",
                        lambda: [_FakeTool(n) for n in names])


def test_registered_mcp_tools_from_live_registry(store, monkeypatch):
    """Reads the live FastMCP registry — the source that makes the check immune to
    a cleared logs/ dir."""
    _mock_live_tools(monkeypatch, _REQUIRED_MCP)
    assert _REQUIRED_MCP <= store._registered_mcp_tools()


def test_toolchain_mcp_ok_without_startup_log(store, tmp_path, monkeypatch):
    """Simulate the dashboard "Clear logs": tools_registered.log absent. With the
    live registry populated the check still reports MCP tools ready and does NOT
    block the toolchain — the regression this fix closes."""
    _mock_live_tools(monkeypatch, _REQUIRED_MCP)
    monkeypatch.setattr(store._paths, "LOGS_DIR", tmp_path)
    assert not (tmp_path / "tools_registered.log").exists()
    store._HEALTH_CACHE.update(ts=0, data=None)
    s = store.toolchain_status()
    mcp = next(c for c in s["components"] if c["name"] == "MCP tools")
    assert mcp["ok"] is True
    assert "6/6" in mcp["detail"]


def test_registered_mcp_tools_falls_back_to_startup_log(store, tmp_path, monkeypatch):
    """When the live registry yields nothing, fall back to logs/tools_registered.log."""
    _mock_live_tools(monkeypatch, [])
    monkeypatch.setattr(store._paths, "LOGS_DIR", tmp_path)
    (tmp_path / "tools_registered.log").write_text(
        "REGISTERED: scan\nREGISTERED: report\nTOTAL: 2\n", encoding="utf-8")
    assert store._registered_mcp_tools() == {"scan", "report"}


def test_registered_mcp_tools_live_error_falls_back(store, tmp_path, monkeypatch):
    """Live-registry read raises → caught → falls back to the startup log."""
    import mcp_server._app as _app

    def _boom():
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(_app.mcp._tool_manager, "list_tools", _boom)
    monkeypatch.setattr(store._paths, "LOGS_DIR", tmp_path)
    (tmp_path / "tools_registered.log").write_text("REGISTERED: session\n", encoding="utf-8")
    assert store._registered_mcp_tools() == {"session"}


def test_registered_mcp_tools_unreadable_log_is_failsoft(store, tmp_path, monkeypatch):
    """Live registry empty AND the log path unreadable → returns empty, never raises."""
    _mock_live_tools(monkeypatch, [])
    monkeypatch.setattr(store._paths, "LOGS_DIR", tmp_path)
    (tmp_path / "tools_registered.log").mkdir()   # exists() True but read_text() raises
    assert store._registered_mcp_tools() == set()


def test_overview_surfaces_garak_and_subtab_badges():
    """UX: the Overview surfaces top garak results (air-garak-lite) so output isn't
    hidden behind a sub-tab, and the ai-redteam.js cache version is bumped."""
    tab = open("dashboard/tabs/ai-redteam.html").read()
    assert 'id="air-garak-lite"' in tab
    shell = client.get("/").text
    assert "ai-redteam.js?v=25" in shell


def test_record_garak_status(store):
    store.record_garak_status({"running": True, "probe": "dan.DanInTheWild", "attempts": 42})
    gs = store.get()["garak_status"]
    assert gs["running"] is True and gs["probe"] == "dan.DanInTheWild" and gs["attempts"] == 42
    assert gs["ts"]
    store.record_garak_status({"running": False})
    assert store.get()["garak_status"]["running"] is False


# ── depth ladder: transform recording + depth_summary ("deeper and deeper") ──

def test_record_transform_and_depth_summary(store):
    store.record_transform("encode", ["base64"], "base")
    store.record_transform("encode", ["base64", "rot13", "homoglyph"], "cipher")  # stack of 3
    store.record_transform("bijection", "letters", "")
    store.record_attack({"jailbroken": False, "attempts": 8,
                         "best": {"technique": "roleplay", "transform": "base64"},
                         "transcript": [{"technique": "authority", "transform": "zero_width"}],
                         "reproducibility": {"k": 2, "n": 5}}, goal="leak", target="t")
    d = store.depth_summary()
    assert d["transform_actions"] == 3
    assert d["transform_distinct_chains"] == 3
    assert d["transform_max_stack"] == 3            # the 3-chain stack
    assert d["redteam_families"] == 2               # roleplay + authority
    assert d["redteam_encodings"] == 2              # base64 + zero_width
    assert d["reproductions"] == 1


def test_depth_summary_empty_is_all_zero(store):
    d = store.depth_summary()
    assert d == {"transform_actions": 0, "transform_distinct_chains": 0, "transform_max_stack": 0,
                 "redteam_families": 0, "redteam_encodings": 0, "reproductions": 0}
