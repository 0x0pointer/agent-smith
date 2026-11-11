"""Tests for mcp_server.scan_engine.planner — focused testing-phase guidance."""
from unittest.mock import patch

from mcp_server.scan_engine import planner


def _matrix():
    return {
        "endpoints": [{"id": "ep1", "path": "/login", "method": "POST", "auth_context": "none"}],
        "matrix": [
            {"id": "c1", "endpoint_id": "ep1", "param": "u", "param_type": "body_json",
             "injection_type": "sqli", "status": "pending"},
            {"id": "c2", "endpoint_id": "ep1", "param": "u", "param_type": "body_json",
             "injection_type": "xss", "status": "pending"},
        ],
    }


def test_add_testing_actions_drives_focused_batch():
    """Continuous drive: hand the next focused batch (endpoint-grouped) with a
    concrete command per cell + progress, framed as 'work the matrix'. Anti-grind
    lives in the framing (real probes, honest closures) + the completion gate, not
    in starving the model of guidance."""
    required: list = []
    recommended: list = []
    with patch.object(planner, "get_matrix", return_value=_matrix()):
        planner._add_testing_actions(required, recommended, "http://t")
    assert len(required) == 1
    msg = required[0]
    # both cells on the focused endpoint are handed as a batch, sqli first
    assert "cell c1" in msg and "cell c2" in msg
    assert "WORK THE MATRIX" in msg
    assert "overall" in msg            # progress is surfaced
    assert "sqlmap" in msg.lower() or "/login" in msg


def test_add_testing_actions_local_profile_is_advisory():
    """Local profile (enforce_coverage=False): the next batch is surfaced as OPTIONAL
    guidance in `recommended`, NOT a required 'WORK THE MATRIX … scan finishes when
    the matrix is worked' directive. That per-turn pressure on an unservable 700-cell
    matrix is what made a small local model spin and stall — restored to advisory."""
    import mcp_server.scan_engine.budget as budget
    required: list = []
    recommended: list = []
    with patch.object(planner, "get_matrix", return_value=_matrix()), \
         patch.object(budget, "get_profile",
                      return_value={"next_batch_size": 3, "enforce_coverage": False}):
        planner._add_testing_actions(required, recommended, "http://t")
    assert required == []                       # no hard "WORK THE MATRIX" directive
    assert any("Optional coverage" in r and "advisory" in r for r in recommended)
    # cells are still surfaced so the model CAN pursue them if useful
    assert any("cell c1" in r for r in recommended)


def test_add_testing_actions_done_when_all_addressed():
    required: list = []
    recommended: list = []
    data = _matrix()
    for c in data["matrix"]:
        c["status"] = "tested_clean"
    with patch.object(planner, "get_matrix", return_value=data):
        planner._add_testing_actions(required, recommended, "http://t")
    assert required == []
    assert any("All cells addressed" in r for r in recommended)


# ── _inject_pending_gates — required-before-completion, not drop-everything-NOW ──

def test_inject_pending_gates_lets_model_finish_recon_first():
    """The chain directive must read as a completion-time requirement that lets the
    model finish its current recon/mapping step — not an insistent 'invoke NOW,
    before any other action, do not defer' that yanks it mid-recon."""
    required = []
    gate = {"id": "auth_coverage", "required_skills": ["credential-audit"],
            "trigger": "auth endpoint /login"}
    with patch("core.session.pending_gates", return_value=[gate]), \
         patch("core.session.get", return_value={"skill_history": []}):
        planner._inject_pending_gates(required)
    assert len(required) == 1
    msg = required[0].lower()
    assert "credential-audit" in msg
    assert "before completion" in msg
    assert "finish your current recon" in msg
    # No drop-everything-now insistence
    assert "before any other action" not in msg
    assert "invoke /credential-audit now" not in msg
    assert "do not defer" not in msg


def test_inject_pending_gates_skips_already_invoked_skill():
    required = []
    gate = {"id": "auth_coverage", "required_skills": ["credential-audit"], "trigger": "auth"}
    with patch("core.session.pending_gates", return_value=[gate]), \
         patch("core.session.get", return_value={"skill_history": [{"skill": "credential-audit"}]}):
        planner._inject_pending_gates(required)
    assert required == []   # skill already chained → no directive


# ── KB recall hints (plan 5.1 §7 / D1-D2) ────────────────────────────────────

def _kb_with_kinds(tmp_path, kinds):
    """Build a kb/index.db containing one doc per kind; point kb_mod at it."""
    from core import kb as kb_mod
    kb_root = tmp_path / "kb"
    kb_root.mkdir(exist_ok=True)
    monkey_paths = {
        "KB_ROOT": kb_root, "SOURCES_DIR": kb_root / "sources",
        "RAW_DIR": kb_root / "sources" / "_raw", "SESSIONS_DIR": kb_root / "sessions",
        "INDEX_DB": kb_root / "index.db", "MANIFEST": kb_root / "MANIFEST.json",
    }
    con = kb_mod.open_index(kb_root / "index.db", create=True)
    for k in kinds:
        kb_mod.replace_source(con, f"kb:{k}", [{
            "source": f"kb:{k}/one", "kind": k, "title": k, "tags": [],
            "text": f"{k} content", "untrusted": False}])
    con.close()
    planner._KB_HINT_CACHE = {"checked_at": 0.0, "kinds": set()}   # drop cross-test cache
    return monkey_paths


def test_kb_recall_hint_for_fingerprinted_tech(tmp_path, monkeypatch):
    """D1: a known technology gets ONE local-KB recall suggestion (deduped)."""
    from core import kb as kb_mod
    monkeypaths = _kb_with_kinds(tmp_path, {"cve", "exploit"})
    for attr, val in monkeypaths.items():
        monkeypatch.setattr(kb_mod, attr, val)
    monkeypatch.setattr(planner, "_kb_hint_suggested", {})
    sess = {"id": "s1", "known_assets": {"technologies": ["Flask:2.0.1"]}}
    rec = []
    with patch("core.session.get", return_value=sess):
        planner._add_kb_recall_hints(rec)
        planner._add_kb_recall_hints(rec)          # second call must dedupe
    assert len(rec) == 1
    assert "recall" in rec[0] and "Flask:2.0.1" in rec[0]


def test_kb_recall_hint_quiet_without_exploit_kinds(tmp_path, monkeypatch):
    """No cve/exploit/nuclei kinds in the KB → no suggestion (stay quiet)."""
    from core import kb as kb_mod
    monkeypaths = _kb_with_kinds(tmp_path, {"skill_ref"})
    for attr, val in monkeypaths.items():
        monkeypatch.setattr(kb_mod, attr, val)
    monkeypatch.setattr(planner, "_kb_hint_suggested", {})
    sess = {"id": "s1", "known_assets": {"technologies": ["Flask:2.0.1"]}}
    rec = []
    with patch("core.session.get", return_value=sess):
        planner._add_kb_recall_hints(rec)
    assert rec == []


def test_cve_gate_points_at_local_kb_first():
    """D1: a CVE-triggered gate appends the recall-before-web hint."""
    required = []
    gate = {"id": "analyze_cve", "required_skills": ["analyze-cve"],
            "trigger": "CVE identified: CVE-2023-25577"}
    with patch("core.session.pending_gates", return_value=[gate]), \
         patch("core.session.get", return_value={"skill_history": []}):
        planner._inject_pending_gates(required)
    assert len(required) == 1
    assert "recall" in required[0] and "cve-2023-25577" in required[0]
    assert "scope:'kb'" in required[0]
