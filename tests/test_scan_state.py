"""mcp_server.scan_engine.state.get_state — findings / escalation counters."""
from mcp_server.scan_engine import state as st


def test_state_counts_findings_and_pending_leads(monkeypatch):
    """`findings` is the filed-findings count (not vulnerable coverage cells) and
    `pending_escalations` reads the leads. Both used to be 0 forever: the import
    named a `findings_store` that core.findings never defined, and the bare except
    swallowed the ImportError."""
    from core import findings as findings_mod
    monkeypatch.setattr(st.scan_session, "get", lambda: {"status": "running", "target": "http://t"})
    monkeypatch.setattr(st.scan_session, "remaining", lambda _s: {})
    monkeypatch.setattr(st.cost_tracker, "get_summary", lambda: {})
    monkeypatch.setattr(st, "get_matrix", lambda: {"meta": {}, "endpoints": [], "matrix": []})
    monkeypatch.setattr(findings_mod, "_load", lambda: {"findings": [
        {"id": "a", "escalation_leads": [{"status": "pending"}, {"status": "done"}]},
        {"id": "b", "escalation_leads": [{"status": "pending"}]},
        {"id": "c", "status": "false_positive", "escalation_leads": [{"status": "pending"}]},
    ]})
    s = st.get_state()
    assert s["findings"] == 2
    assert s["pending_escalations"] == 2
    assert s["vulnerable_cells"] == 0
