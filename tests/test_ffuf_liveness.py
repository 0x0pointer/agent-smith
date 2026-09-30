"""
Tests for issue #180 — wordlist/ffuf paths must not inflate the coverage matrix.

Three coupled behaviours are exercised:
  1. provenance — ffuf-derived paths are labelled ``discovered_by="ffuf"``, not
     the hardcoded ``"spider"`` that made them unfilterable;
  2. liveness — a fuzz path registers as CONFIRMED only when its response proves
     it exists (non-404/403 and differing from the not-found baseline); a 403 /
     soft-404 / unprobed-tail path registers as a CANDIDATE, and an exact 404 is
     dropped outright;
  3. accounting — the candidate flag is stamped on the endpoint and every cell,
     ``_recount`` splits confirmed vs candidate counters (legacy matrices default
     to confirmed), and the completion gates exclude candidate cells so phantom
     paths can't wedge coverage.
"""
import json as _json

import pytest

import core.coverage as cov
from mcp_server.scan_engine import discovery as disc


# ── provenance: _spider_endpoints honours the source label ─────────────────────

def test_spider_endpoints_label_defaults_to_spider():
    eps = disc._spider_endpoints(["http://t/admin", "http://t/login"])
    assert eps and all(e["discovered_by"] == "spider" for e in eps)


def test_spider_endpoints_label_threads_source():
    eps = disc._spider_endpoints(["http://t/admin", "http://t/login"], source="ffuf")
    assert eps and all(e["discovered_by"] == "ffuf" for e in eps)


# ── liveness classification of wordlist hits ───────────────────────────────────

@pytest.mark.asyncio
async def test_classify_fuzz_confirmed_vs_candidate_vs_dropped(monkeypatch):
    # Baseline probe (a random path) returns the target's soft-404: 200 + 500 bytes.
    BASELINE_BODY = "x" * 500

    async def fake_fetch(url):
        if url.endswith(".nonexistent"):
            return 200, BASELINE_BODY                 # baseline: catch-all 200
        if url.endswith("/real"):
            return 200, "y" * 4000                    # 200, unlike baseline → confirmed
        if url.endswith("/admin"):
            return 403, ""                            # 403 → candidate (not confirmed)
        if url.endswith("/softish"):
            return 200, "x" * 495                     # matches baseline within tol → candidate
        if url.endswith("/gone"):
            return 404, ""                            # exact 404 → dropped
        return 500, ""

    monkeypatch.setattr(disc, "_fetch", fake_fetch)

    inv = [
        {"path": "/real", "method": "GET", "params": [], "discovered_by": "ffuf"},
        {"path": "/admin", "method": "GET", "params": [], "discovered_by": "ffuf"},
        {"path": "/softish", "method": "GET", "params": [], "discovered_by": "ffuf"},
        {"path": "/gone", "method": "GET", "params": [], "discovered_by": "ffuf"},
    ]
    kept, dropped = await disc._classify_fuzz_paths("http://t", inv)
    by_path = {e["path"]: e for e in kept}

    assert dropped == 1 and "/gone" not in by_path        # exact 404 dropped
    assert by_path["/real"]["candidate"] is False          # proven live
    assert by_path["/admin"]["candidate"] is True          # 403 → candidate
    assert by_path["/softish"]["candidate"] is True        # baseline match → candidate


@pytest.mark.asyncio
async def test_unstable_target_no_false_candidate(monkeypatch):
    """When two baseline probes disagree, the target isn't a stable catch-all, so a
    real ffuf-only 200 endpoint must NOT be demoted to candidate on length alone."""
    calls = {"n": 0}

    async def fake_fetch(url):
        if url.endswith(".nonexistent"):
            # two random probes return DIFFERENT sizes → no trustworthy baseline
            calls["n"] += 1
            return 200, "z" * (100 if calls["n"] % 2 else 4000)
        if url.endswith("/api/status"):
            return 200, "z" * 105          # near one probe, but baseline is untrusted
        return 500, ""

    monkeypatch.setattr(disc, "_fetch", fake_fetch)
    inv = [{"path": "/api/status", "method": "GET", "params": [], "discovered_by": "ffuf"}]
    kept, dropped = await disc._classify_fuzz_paths("http://t", inv)
    assert dropped == 0 and len(kept) == 1
    assert kept[0]["candidate"] is False       # 200, no trusted baseline → confirmed


@pytest.mark.asyncio
async def test_classify_fuzz_probe_error_is_candidate_not_dropped(monkeypatch):
    async def boom(url):
        raise RuntimeError("network down")

    monkeypatch.setattr(disc, "_fetch", boom)
    inv = [{"path": "/x", "method": "GET", "params": [], "discovered_by": "ffuf"}]
    kept, dropped = await disc._classify_fuzz_paths("http://t", inv)
    assert dropped == 0 and len(kept) == 1
    assert kept[0]["candidate"] is True                    # never confirm on doubt


@pytest.mark.asyncio
async def test_classify_fuzz_probes_all_paths_no_silent_tail(monkeypatch):
    """Every fuzz path is probed or explicitly marked candidate — none silently
    registers as real past the old 80-path cap."""
    monkeypatch.setattr(disc, "_MAX_FUZZ_VERIFY", 5)

    async def fake_fetch(url):
        if url.endswith(".nonexistent"):
            return 404, ""                                 # no baseline body
        return 200, "live"                                 # every probed path is live

    monkeypatch.setattr(disc, "_fetch", fake_fetch)
    inv = [{"path": f"/p{i}", "method": "GET", "params": [], "discovered_by": "ffuf"}
           for i in range(12)]
    kept, dropped = await disc._classify_fuzz_paths("http://t", inv)
    assert len(kept) == 12 and dropped == 0
    # first 5 probed → confirmed; the 7-path tail beyond the budget → candidate
    assert sum(1 for e in kept if not e["candidate"]) == 5
    assert sum(1 for e in kept if e["candidate"]) == 7


# ── end-to-end: ffuf crawl_source routes through classification ────────────────

@pytest.mark.asyncio
async def test_discover_and_register_ffuf_marks_candidates(monkeypatch, coverage_file):
    async def fake_fetch(url):
        if url.endswith(".nonexistent"):
            return 200, "shell" * 100                       # catch-all baseline
        if url.endswith("/real"):
            return 200, "unique-content" * 50               # confirmed
        if "openapi" in url or "swagger" in url or "api-docs" in url:
            return 404, ""
        return 403, ""                                       # everything else 403 → candidate

    monkeypatch.setattr(disc, "_fetch", fake_fetch)

    out = await disc.discover_and_register(
        "http://t", ["http://t/real", "http://t/.bash_history", "http://t/.bashrc"],
        crawl_source="ffuf",
    )
    assert out["registered"] == 3
    assert out["registered_confirmed"] == 1                 # only /real proven live
    assert out["registered_candidate"] == 2                 # the two dotfiles 403'd

    data = _json.loads(coverage_file.read_text())
    eps = {e["path"]: e for e in data["endpoints"]}
    assert eps["/real"]["discovered_by"] == "ffuf" and eps["/real"]["candidate"] is False
    assert eps["/.bash_history"]["candidate"] is True
    # candidate endpoints' cells are flagged, so the split counters are honest
    assert data["meta"]["candidate_cells"] > 0
    assert data["meta"]["confirmed_cells"] < data["meta"]["total_cells"]


# ── accounting: add_endpoint candidate flag + _recount split ───────────────────

@pytest.mark.asyncio
async def test_add_endpoint_candidate_stamps_flag_and_counters(coverage_file):
    r = await cov.add_endpoint("/maybe", "GET",
                               [{"name": "q", "type": "query", "value_hint": "string"}],
                               discovered_by="ffuf", candidate=True)
    assert not r["dedup"]
    data = _json.loads(coverage_file.read_text())
    ep = data["endpoints"][0]
    assert ep["candidate"] is True
    cells = [c for c in data["matrix"] if c["endpoint_id"] == ep["id"]]
    assert cells and all(c["candidate"] is True for c in cells)
    # every cell here is candidate → confirmed denominator is zero
    assert data["meta"]["candidate_cells"] == len(cells)
    assert data["meta"]["confirmed_cells"] == 0
    assert data["meta"]["candidate_endpoints"] == 1


@pytest.mark.asyncio
async def test_confirmed_registration_upgrades_prior_candidate(coverage_file):
    await cov.add_endpoint("/thing", "GET", [], discovered_by="ffuf", candidate=True)
    # a real crawl later finds the same route → upgrade to confirmed
    r = await cov.add_endpoint("/thing", "GET", [], discovered_by="spider", candidate=False)
    assert r["dedup"] and r["upgraded_confirmed"] is True
    data = _json.loads(coverage_file.read_text())
    assert data["endpoints"][0]["candidate"] is False
    assert all(not c["candidate"] for c in data["matrix"])
    assert data["meta"]["candidate_cells"] == 0


@pytest.mark.asyncio
async def test_legacy_cell_without_flag_counts_as_confirmed(coverage_file):
    # simulate a pre-#180 matrix: cells/endpoints have no `candidate` key
    data = cov._load()
    data["endpoints"].append({"id": "ep-1", "path": "/x", "_normalized": "/x",
                              "method": "GET", "params": []})
    data["matrix"].append({"id": "c-1", "endpoint_id": "ep-1", "param": "_endpoint",
                           "param_type": "endpoint", "injection_type": "cors",
                           "status": "pending"})
    cov._recount(data)
    assert data["meta"]["candidate_cells"] == 0
    assert data["meta"]["confirmed_cells"] == 1
    assert data["meta"]["candidate_endpoints"] == 0


# ── completion floor excludes candidate cells ──────────────────────────────────

def test_floor_view_excludes_candidate_cells():
    from mcp_server.session_tools import coverage_gates as cg
    # 2 confirmed cells (1 addressed) + 8 candidate cells (all pending). The raw
    # pct is 1/10 = 10%, but over CONFIRMED cells it is 1/2 = 50% ≥ the 40% floor.
    matrix = (
        [{"injection_type": "sqli", "status": "tested_clean"},
         {"injection_type": "xss", "status": "pending"}]
        + [{"injection_type": "sqli", "status": "pending", "candidate": True}
           for _ in range(8)]
    )
    cov_data = {"matrix": matrix}
    total, addressed = len(matrix), 1
    f_total, f_addr, f_pct = cg._floor_view(cov_data, total, addressed)
    assert f_total == 2 and f_addr == 1 and f_pct == 50.0
    assert cg._low_coverage_blocker(cov_data, total, addressed, addressed / total * 100) is None
