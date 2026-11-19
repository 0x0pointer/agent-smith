"""World-Model Graph wiring — Fix 5 (cross-run persistence substrate).

Covers the serialization substrate, the recon-asset snapshot (NO secrets / no
verdicts), the opt-in prior-run merge, and the matrix-as-view projection that the
full authority inversion would build on.
"""
import pytest

from core.graph import model as m
from core.graph import persist
from core.graph.views import coverage_view


def _asset_graph():
    g = m.Graph()
    g.add_node("host:t.test", m.HOST, "t.test")
    g.add_node("endpoint:t.test:/order", m.ENDPOINT, "/order", path="/order", method="GET")
    g.add_node("param:t.test:/order:id", m.PARAM, "id", param_type="query")
    g.add_edge("host:t.test", "endpoint:t.test:/order", m.HOSTS)
    g.add_edge("endpoint:t.test:/order", "param:t.test:/order:id", m.HAS_PARAM)
    return g


# ── serialization substrate ──────────────────────────────────────────────────

def test_serialize_deserialize_round_trip():
    g = _asset_graph()
    g2 = persist.deserialize(persist.serialize(g))
    assert set(g2.nodes) == set(g.nodes)
    assert len(g2.edges) == len(g.edges)
    assert g2.nodes["endpoint:t.test:/order"].attrs["path"] == "/order"


def test_coverage_view_projects_matrix_from_graph():
    """The matrix IS a view over the graph (the projection the authority inversion
    would make canonical) — validate the direction is sound."""
    g = m.Graph()
    g.add_node("endpoint:t:/x", m.ENDPOINT, "/x", path="/x", method="GET")
    g.add_edge("endpoint:t:/x", "inj:ssti", m.TESTED_FOR, param="q", status="pending")
    view = coverage_view(g)
    assert any(c["injection_type"] == "ssti" and c["status"] == "pending" for c in view["matrix"])


# ── asset snapshot excludes secrets + verdicts ───────────────────────────────

def test_asset_subgraph_excludes_secrets_and_findings():
    g = _asset_graph()
    g.add_node("credential:admin", m.CREDENTIAL, "admin:hunter2", secret="hunter2")
    g.add_node("finding:f1", m.FINDING, "SQLi", severity="high")
    g.add_edge("endpoint:t.test:/order", "inj:sqli", m.TESTED_FOR, status="vulnerable")
    sub = persist._asset_subgraph(g)
    kinds = {n["kind"] for n in sub["nodes"]}
    assert m.CREDENTIAL not in kinds and m.FINDING not in kinds
    assert m.HOST in kinds and m.ENDPOINT in kinds
    blob = str(sub)
    assert "hunter2" not in blob and "vulnerable" not in blob  # no secret, no verdict


# ── snapshot save / load / merge ─────────────────────────────────────────────

@pytest.fixture
def _snapdir(tmp_path, monkeypatch):
    monkeypatch.setattr(persist, "_snapshot_dir", lambda: tmp_path)
    return tmp_path


def test_save_and_load_snapshot(_snapdir):
    assert persist.save_snapshot(_asset_graph(), "http://t.test") is True
    snap = persist.load_snapshot("http://t.test")
    assert snap and any(n["id"] == "host:t.test" for n in snap["nodes"])


def test_load_missing_snapshot_is_none(_snapdir):
    assert persist.load_snapshot("http://never.seen") is None


def test_merge_prior_assets_tags_provenance(_snapdir):
    persist.save_snapshot(_asset_graph(), "http://t.test")
    fresh = m.Graph()
    fresh.add_node("host:t.test", m.HOST, "t.test")  # already present — must not be clobbered
    added = persist.merge_prior_assets(fresh, "http://t.test")
    assert added >= 1
    ep = fresh.nodes["endpoint:t.test:/order"]
    assert ep.attrs.get("provenance") == "prior_run" and ep.attrs.get("candidate") is True
    assert fresh.nodes["host:t.test"].attrs.get("provenance") != "prior_run"  # existing untouched


def test_merge_without_snapshot_returns_zero(_snapdir):
    assert persist.merge_prior_assets(m.Graph(), "http://nothing") == 0


def test_crossrun_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SMITH_GRAPH_CROSSRUN", raising=False)
    assert persist.crossrun_enabled() is False
    monkeypatch.setenv("SMITH_GRAPH_CROSSRUN", "1")
    assert persist.crossrun_enabled() is True


def test_target_key_sanitizes_host():
    assert persist._target_key("http://t.test:8080/path") == "t.test"
    assert persist._target_key("https://a b/c") == "a_b"
