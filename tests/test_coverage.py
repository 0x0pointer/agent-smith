"""
Tests for core.coverage — coverage matrix store.
"""
import json
import pytest
import core.coverage


def _make_artifact(tool: str = "sqlmap") -> str:
    """Create a fake artifact file in _ARTIFACTS_DIR and return its artifact_id."""
    import uuid
    artifact_id = f"{tool}-{uuid.uuid4().hex[:8]}"
    (core.coverage._ARTIFACTS_DIR / f"{artifact_id}.txt").write_text("test output")
    return artifact_id


# ---------------------------------------------------------------------------
# add_endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_add_endpoint_creates_entry(coverage_file):
    result = await core.coverage.add_endpoint(
        path="/login",
        method="POST",
        params=[
            {"name": "username", "type": "body_form", "value_hint": ""},
            {"name": "password", "type": "body_form", "value_hint": ""},
        ],
        discovered_by="spider",
        auth_context="none",
    )
    assert result["dedup"] is False
    assert result["new_cells"] > 0
    assert result["endpoint_id"].startswith("ep-")


@pytest.mark.asyncio
async def test_add_endpoint_persists_to_file(coverage_file):
    await core.coverage.add_endpoint(
        path="/search", method="GET",
        params=[{"name": "q", "type": "query", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    assert len(data["endpoints"]) == 1
    assert data["endpoints"][0]["path"] == "/search"
    assert data["meta"]["total_cells"] > 0


@pytest.mark.asyncio
async def test_add_endpoint_generates_correct_cells_for_path_integer(coverage_file):
    result = await core.coverage.add_endpoint(
        path="/profile/{id}", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    data = json.loads(coverage_file.read_text())
    param_cells = [c for c in data["matrix"] if c["param"] == "id"]
    inj_types = {c["injection_type"] for c in param_cells}
    # path/integer should get: sqli, idor, traversal
    assert inj_types == {"sqli", "idor", "traversal"}


@pytest.mark.asyncio
async def test_add_endpoint_generates_endpoint_level_cells(coverage_file):
    await core.coverage.add_endpoint(
        path="/api/data", method="GET", params=[],
    )
    data = json.loads(coverage_file.read_text())
    ep_cells = [c for c in data["matrix"] if c["param"] == "_endpoint"]
    inj_types = {c["injection_type"] for c in ep_cells}
    assert "cors" in inj_types
    assert "csrf" in inj_types
    assert "security_headers" in inj_types
    assert "rate_limit" in inj_types


@pytest.mark.asyncio
async def test_add_endpoint_dedup_on_normalized_path(coverage_file):
    r1 = await core.coverage.add_endpoint(
        path="/profile/1", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    r2 = await core.coverage.add_endpoint(
        path="/profile/2", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    assert r1["dedup"] is False
    assert r2["dedup"] is True
    data = json.loads(coverage_file.read_text())
    assert len(data["endpoints"]) == 1


@pytest.mark.asyncio
async def test_add_endpoint_different_methods_not_deduped(coverage_file):
    await core.coverage.add_endpoint(
        path="/api/users", method="GET", params=[],
    )
    await core.coverage.add_endpoint(
        path="/api/users", method="POST",
        params=[{"name": "name", "type": "body_json", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    assert len(data["endpoints"]) == 2


@pytest.mark.asyncio
async def test_add_endpoint_query_default_applicability(coverage_file):
    await core.coverage.add_endpoint(
        path="/search", method="GET",
        params=[{"name": "q", "type": "query", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    param_cells = [c for c in data["matrix"] if c["param"] == "q"]
    inj_types = {c["injection_type"] for c in param_cells}
    assert "sqli" in inj_types
    assert "xss" in inj_types
    assert "ssti" in inj_types
    assert "ssrf" in inj_types


@pytest.mark.asyncio
async def test_add_endpoint_body_json_applicability(coverage_file):
    await core.coverage.add_endpoint(
        path="/api/update", method="POST",
        params=[{"name": "data", "type": "body_json", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    param_cells = [c for c in data["matrix"] if c["param"] == "data"]
    inj_types = {c["injection_type"] for c in param_cells}
    assert "nosqli" in inj_types
    assert "prototype" in inj_types
    assert "mass_assignment" in inj_types
    assert "sqli" in inj_types


# ---------------------------------------------------------------------------
# update_cell
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_cell_marks_tested(coverage_file):
    await core.coverage.add_endpoint(
        path="/test", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    data = json.loads(coverage_file.read_text())
    cell = data["matrix"][0]
    # Must pass through in_progress first (integrity rule)
    await core.coverage.update_cell(cell["id"], "in_progress", notes="Starting test")
    artifact_id = _make_artifact("sqlmap")
    ok = await core.coverage.update_cell(
        cell["id"], "tested_clean", notes="No injection found",
        tested_by="sqlmap", artifact_id=artifact_id,
    )
    assert ok is True
    data = json.loads(coverage_file.read_text())
    updated = next(c for c in data["matrix"] if c["id"] == cell["id"])
    assert updated["status"] == "tested_clean"
    assert updated["notes"] == "No injection found"
    assert updated["tested_at"] is not None
    assert updated["tested_by"] == "sqlmap"


@pytest.mark.asyncio
async def test_update_cell_warns_on_skip_in_progress(coverage_file):
    """Skipping in_progress returns an integrity warning string."""
    await core.coverage.add_endpoint(
        path="/test2", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    data = json.loads(coverage_file.read_text())
    cell = data["matrix"][0]
    artifact_id = _make_artifact("http_request")
    result = await core.coverage.update_cell(
        cell["id"], "tested_clean", notes="No injection found",
        tested_by="http_request", artifact_id=artifact_id,
    )
    assert isinstance(result, str)
    assert "INTEGRITY WARNING" in result
    # Cell is still updated (warning, not a blocker)
    data = json.loads(coverage_file.read_text())
    updated = next(c for c in data["matrix"] if c["id"] == cell["id"])
    assert updated["status"] == "tested_clean"


@pytest.mark.asyncio
async def test_update_cell_vulnerable_with_finding(coverage_file):
    await core.coverage.add_endpoint(
        path="/login", method="POST",
        params=[{"name": "user", "type": "body_form", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    sqli_cell = next(c for c in data["matrix"] if c["injection_type"] == "sqli" and c["param"] == "user")
    # Proper flow: pending -> in_progress -> vulnerable
    await core.coverage.update_cell(sqli_cell["id"], "in_progress", notes="Testing SQLi")
    artifact_id = _make_artifact("sqlmap")
    ok = await core.coverage.update_cell(
        sqli_cell["id"], "vulnerable",
        notes="Blind SQLi confirmed", finding_id="finding-123",
        tested_by="sqlmap", artifact_id=artifact_id,
    )
    assert ok is True
    data = json.loads(coverage_file.read_text())
    assert data["meta"]["vulnerable"] == 1


@pytest.mark.asyncio
async def test_update_cell_invalid_status_returns_false(coverage_file):
    await core.coverage.add_endpoint(
        path="/x", method="GET",
        params=[{"name": "a", "type": "query", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    ok = await core.coverage.update_cell(data["matrix"][0]["id"], "bogus")
    assert ok is False


@pytest.mark.asyncio
async def test_update_cell_missing_id_returns_false(coverage_file):
    ok = await core.coverage.update_cell("nonexistent", "in_progress")
    assert ok is False


# ---------------------------------------------------------------------------
# bulk_update
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bulk_update_multiple_cells(coverage_file):
    await core.coverage.add_endpoint(
        path="/api", method="GET", params=[],
    )
    data = json.loads(coverage_file.read_text())
    # Mark in_progress first (proper flow)
    in_progress_updates = [
        {"cell_id": c["id"], "status": "in_progress", "notes": "Starting"}
        for c in data["matrix"][:3]
    ]
    await core.coverage.bulk_update(in_progress_updates)
    # Now mark tested_clean with valid artifact_ids
    updates = [
        {
            "cell_id": c["id"], "status": "tested_clean", "notes": "OK",
            "tested_by": "http_request", "artifact_id": _make_artifact("http_request"),
        }
        for c in data["matrix"][:3]
    ]
    result = await core.coverage.bulk_update(updates)
    assert result["updated"] == 3
    assert result["warnings"] == []
    data = json.loads(coverage_file.read_text())
    assert data["meta"]["tested"] >= 3


@pytest.mark.asyncio
async def test_bulk_update_warns_on_skip_in_progress(coverage_file):
    """Bulk update returns warnings when cells skip in_progress."""
    await core.coverage.add_endpoint(
        path="/api2", method="GET", params=[],
    )
    data = json.loads(coverage_file.read_text())
    updates = [
        {
            "cell_id": c["id"], "status": "tested_clean", "notes": "OK",
            "tested_by": "http_request", "artifact_id": _make_artifact("http_request"),
        }
        for c in data["matrix"][:3]
    ]
    result = await core.coverage.bulk_update(updates)
    assert result["updated"] == 3
    assert len(result["warnings"]) == 3


@pytest.mark.asyncio
async def test_bulk_update_rejects_artifact_mass_reuse_across_injection_types(coverage_file):
    """The single-artifact mass-closure pattern (one HTTP request closing 36
    different injection cells) is now rejected mid-batch. Tests the in-flight
    counting in bulk_update: as each cell closes, future updates in the same
    batch see the new closure and reject after the cap is hit."""
    await core.coverage.add_endpoint(
        path="/api/v1/reset-password", method="POST",
        params=[{"name": "email", "type": "body_json", "value_hint": "string"}],
    )
    data = json.loads(coverage_file.read_text())
    # One artifact, but it'll be cited for multiple injection-type cells.
    artifact_id = _make_artifact("http_request")
    inj_cells = [c for c in data["matrix"] if c["injection_type"] in ("sqli", "xss", "ssti", "cmdi", "ssrf")]
    assert len(inj_cells) >= 5

    updates = [
        {"cell_id": c["id"], "status": "tested_clean", "notes": "OK",
         "tested_by": "http_request", "artifact_id": artifact_id}
        for c in inj_cells
    ]
    result = await core.coverage.bulk_update(updates)
    # First 2 cells (sqli, xss) accepted; the 3rd-5th rejected by the reuse cap.
    assert result["updated"] == 2
    assert result["rejected"] >= 3
    # At least one warning explicitly cites the reuse guard.
    assert any("REJECTED" in w and artifact_id in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_na_warns_on_bypass_required_type(coverage_file):
    """Marking XXE or SQLi as N/A without bypass justification triggers warning."""
    await core.coverage.add_endpoint(
        path="/form", method="POST",
        params=[{"name": "data", "type": "body_form", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    xxe_cell = next(c for c in data["matrix"] if c["injection_type"] == "xxe")
    result = await core.coverage.update_cell(
        xxe_cell["id"], "not_applicable", notes="Not XML"
    )
    assert isinstance(result, str)
    assert "INTEGRITY WARNING" in result
    assert "Content-Type switching" in result


@pytest.mark.asyncio
async def test_na_no_warning_with_proper_justification(coverage_file):
    """N/A with proper justification for bypass-required types returns True."""
    await core.coverage.add_endpoint(
        path="/form2", method="POST",
        params=[{"name": "data", "type": "body_form", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    xxe_cell = next(c for c in data["matrix"] if c["injection_type"] == "xxe")
    result = await core.coverage.update_cell(
        xxe_cell["id"], "not_applicable",
        notes="Tested Content-Type switching to application/xml — server returns 415 Unsupported Media Type"
    )
    assert result is True


# ---------------------------------------------------------------------------
# get_pending
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_pending_returns_all_initially(coverage_file):
    result = await core.coverage.add_endpoint(
        path="/test", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    pending = await core.coverage.get_pending()
    assert len(pending) == result["new_cells"]
    assert all(c["status"] == "pending" for c in pending)


@pytest.mark.asyncio
async def test_get_pending_filtered_by_endpoint(coverage_file):
    r1 = await core.coverage.add_endpoint(
        path="/a", method="GET", params=[],
    )
    r2 = await core.coverage.add_endpoint(
        path="/b", method="GET", params=[],
    )
    pending_a = await core.coverage.get_pending(endpoint_id=r1["endpoint_id"])
    pending_b = await core.coverage.get_pending(endpoint_id=r2["endpoint_id"])
    all_pending = await core.coverage.get_pending()
    assert len(pending_a) + len(pending_b) == len(all_pending)


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reset_clears_everything(coverage_file):
    await core.coverage.add_endpoint(
        path="/test", method="GET",
        params=[{"name": "id", "type": "query", "value_hint": ""}],
    )
    await core.coverage.reset()
    data = json.loads(coverage_file.read_text())
    assert data["meta"]["total_cells"] == 0
    assert data["endpoints"] == []
    assert data["matrix"] == []


# ---------------------------------------------------------------------------
# get_matrix (sync)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_matrix_returns_current_state(coverage_file):
    await core.coverage.add_endpoint(
        path="/test", method="GET",
        params=[{"name": "x", "type": "query", "value_hint": ""}],
    )
    matrix = core.coverage.get_matrix()
    assert len(matrix["endpoints"]) == 1
    assert matrix["meta"]["total_cells"] > 0


# ---------------------------------------------------------------------------
# Meta counters
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_meta_counters_accurate(coverage_file):
    await core.coverage.add_endpoint(
        path="/test", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    data = json.loads(coverage_file.read_text())
    # All param cells + endpoint-level cells
    total = data["meta"]["total_cells"]
    assert total > 0
    assert data["meta"]["tested"] == 0
    assert data["meta"]["vulnerable"] == 0

    # Mark one tested, one vulnerable, one N/A.
    # Vulnerable closures now require a finding_id (see _validate_finding_link
    # in core/coverage.py) — the validator forces Smith to call
    # report(action='finding') first instead of auto-filing on his behalf.
    cells = data["matrix"]
    await core.coverage.update_cell(cells[0]["id"], "in_progress")
    await core.coverage.update_cell(
        cells[0]["id"], "tested_clean",
        tested_by="sqlmap", artifact_id=_make_artifact("sqlmap"),
    )
    await core.coverage.update_cell(cells[1]["id"], "in_progress")
    await core.coverage.update_cell(
        cells[1]["id"], "vulnerable",
        tested_by="sqlmap", artifact_id=_make_artifact("sqlmap"), finding_id="finding-1",
    )
    await core.coverage.update_cell(cells[2]["id"], "not_applicable")

    data = json.loads(coverage_file.read_text())
    assert data["meta"]["tested"] == 2  # tested_clean + vulnerable
    assert data["meta"]["vulnerable"] == 1
    assert data["meta"]["not_applicable"] == 1


# ---------------------------------------------------------------------------
# cell_has_test_evidence — the completion-gate evidence predicate
# ---------------------------------------------------------------------------

def test_cell_evidence_artifact_only_is_evidenced():
    # The deadlock fix: a cell closed with a real artifact_id but an empty
    # tested_by IS evidenced. Keying the completion gates on tested_by alone
    # made such cells permanently un-completable after a context compaction.
    from core.coverage import cell_has_test_evidence
    assert cell_has_test_evidence({"artifact_id": "http_request_120000_abcd1234", "tested_by": ""})


def test_cell_evidence_tested_by_only_is_evidenced():
    # Back-compat: older matrices recorded only the free-text tested_by.
    from core.coverage import cell_has_test_evidence
    assert cell_has_test_evidence({"artifact_id": "", "tested_by": "sqlmap"})


def test_cell_evidence_neither_is_unevidenced():
    from core.coverage import cell_has_test_evidence
    assert not cell_has_test_evidence({"artifact_id": "", "tested_by": ""})
    assert not cell_has_test_evidence({})


# ---------------------------------------------------------------------------
# _validate_artifact_reuse — single-artifact mass-closure guard
# ---------------------------------------------------------------------------

def test_validate_artifact_reuse_first_close_is_fine():
    """The first cell to cite an artifact is always accepted — nothing to reuse yet."""
    from core.coverage.validation import _validate_artifact_reuse
    target = {"id": "c1", "injection_type": "sqli", "artifact_id": ""}
    assert _validate_artifact_reuse("art_X", "tested_clean", target, []) == ""


def test_validate_artifact_reuse_one_sibling_is_fine():
    """Up to 1 prior injection-type cell on the same artifact is allowed — a single
    discriminating payload can plausibly tell you about its target injection PLUS one
    obvious adjacent type (e.g. sqli payload that's also reflected → also clears xss)."""
    from core.coverage.validation import _validate_artifact_reuse
    target = {"id": "c2", "injection_type": "xss", "artifact_id": ""}
    matrix = [{"id": "c1", "injection_type": "sqli", "artifact_id": "art_X", "status": "tested_clean"}]
    assert _validate_artifact_reuse("art_X", "tested_clean", target, matrix) == ""


def test_validate_artifact_reuse_rejects_third_distinct_injection_type():
    """The 3rd injection-type cell to claim the same artifact gets rejected — one
    request cannot legitimately test sqli + xss + ssti + ... at the same time."""
    from core.coverage.validation import _validate_artifact_reuse
    target = {"id": "c3", "injection_type": "ssti", "artifact_id": ""}
    matrix = [
        {"id": "c1", "injection_type": "sqli", "artifact_id": "art_X", "status": "tested_clean"},
        {"id": "c2", "injection_type": "xss",  "artifact_id": "art_X", "status": "tested_clean"},
    ]
    msg = _validate_artifact_reuse("art_X", "tested_clean", target, matrix)
    assert "REJECTED" in msg
    assert "art_X" in msg
    assert "specific" in msg.lower() or "discriminating" in msg.lower()


def test_validate_artifact_reuse_response_header_types_are_exempt():
    """security_headers/cors cells legitimately share a single response artifact —
    one GET truthfully surfaces both. They don't count toward the cap, and they
    aren't rejected when piled on the same artifact."""
    from core.coverage.validation import _validate_artifact_reuse
    target = {"id": "c5", "injection_type": "cors", "artifact_id": ""}
    matrix = [
        {"id": "c1", "injection_type": "security_headers", "artifact_id": "art_X", "status": "tested_clean"},
        {"id": "c2", "injection_type": "security_headers", "artifact_id": "art_X", "status": "tested_clean"},
        {"id": "c3", "injection_type": "cors",             "artifact_id": "art_X", "status": "tested_clean"},
    ]
    # The new target is a response-header type → exempt outright.
    assert _validate_artifact_reuse("art_X", "tested_clean", target, matrix) == ""


def test_validate_artifact_reuse_header_siblings_dont_count_against_cap():
    """The cap counts only payload-requiring siblings; response-header siblings
    are exempt so they don't artificially block legitimate testing."""
    from core.coverage.validation import _validate_artifact_reuse
    # Target is a real injection type — sqli.
    target = {"id": "c5", "injection_type": "sqli", "artifact_id": ""}
    # 2 response-header siblings + 0 injection siblings → cap not hit.
    matrix = [
        {"id": "c1", "injection_type": "security_headers", "artifact_id": "art_X", "status": "tested_clean"},
        {"id": "c2", "injection_type": "cors",             "artifact_id": "art_X", "status": "tested_clean"},
    ]
    assert _validate_artifact_reuse("art_X", "tested_clean", target, matrix) == ""


def test_validate_artifact_reuse_does_not_count_pending_cells():
    """A pending cell that happens to carry an artifact_id (e.g. set during
    in_progress) doesn't count as a closure — only tested_clean/vulnerable do."""
    from core.coverage.validation import _validate_artifact_reuse
    target = {"id": "c3", "injection_type": "ssti", "artifact_id": ""}
    matrix = [
        {"id": "c1", "injection_type": "sqli", "artifact_id": "art_X", "status": "pending"},
        {"id": "c2", "injection_type": "xss",  "artifact_id": "art_X", "status": "pending"},
    ]
    assert _validate_artifact_reuse("art_X", "tested_clean", target, matrix) == ""


def test_validate_artifact_reuse_skipped_for_non_final_status():
    """Reuse-cap only applies to tested_clean/vulnerable. Marking pending or
    in_progress doesn't trip it."""
    from core.coverage.validation import _validate_artifact_reuse
    target = {"id": "c3", "injection_type": "ssti", "artifact_id": ""}
    matrix = [
        {"id": "c1", "injection_type": "sqli", "artifact_id": "art_X", "status": "tested_clean"},
        {"id": "c2", "injection_type": "xss",  "artifact_id": "art_X", "status": "tested_clean"},
    ]
    assert _validate_artifact_reuse("art_X", "in_progress", target, matrix) == ""


# ---------------------------------------------------------------------------
# unregistered_finding_paths — discovery-before-testing predicate
# ---------------------------------------------------------------------------

def test_unregistered_finding_paths_flags_untested_endpoints():
    from core.coverage import unregistered_finding_paths
    cov = {"endpoints": [{"path": "/login", "_normalized": "/login"}]}
    fnd = {"findings": [
        {"target": "http://t/login", "status": "confirmed"},      # registered → ok
        {"target": "http://t/transfer", "status": "confirmed"},   # not registered
        {"target": "http://t/admin/delete/42"},                   # not registered, normalized
    ]}
    assert unregistered_finding_paths(fnd, cov) == ["/admin/delete/{id}", "/transfer"]


def test_unregistered_finding_paths_registered_ok():
    from core.coverage import unregistered_finding_paths
    cov = {"endpoints": [{"path": "/transfer", "_normalized": "/transfer"}]}
    assert unregistered_finding_paths({"findings": [{"target": "http://t/transfer"}]}, cov) == []


def test_unregistered_finding_paths_empty_matrix_returns_empty():
    from core.coverage import unregistered_finding_paths
    fnd = {"findings": [{"target": "http://t/x"}]}
    assert unregistered_finding_paths(fnd, {"endpoints": []}) == []


def test_unregistered_finding_paths_ignores_false_positive():
    from core.coverage import unregistered_finding_paths
    cov = {"endpoints": [{"path": "/login", "_normalized": "/login"}]}
    fnd = {"findings": [{"target": "http://t/ghost", "status": "false_positive"}]}
    assert unregistered_finding_paths(fnd, cov) == []


# ---------------------------------------------------------------------------
# select_next_batch / get_next_batch — focused step-by-step testing loop
# ---------------------------------------------------------------------------

def _batch_data(extra_cells=None):
    return {
        "endpoints": [
            {"id": "ep1", "path": "/login", "method": "POST", "auth_context": "none"},
            {"id": "ep2", "path": "/blog", "method": "GET", "auth_context": "none"},
        ],
        "matrix": [
            {"id": "c1", "endpoint_id": "ep1", "param": "u", "param_type": "body_json", "injection_type": "xss", "status": "pending"},
            {"id": "c2", "endpoint_id": "ep1", "param": "u", "param_type": "body_json", "injection_type": "sqli", "status": "pending"},
            {"id": "c3", "endpoint_id": "ep2", "param": "_endpoint", "param_type": "endpoint", "injection_type": "cors", "status": "pending"},
            *(extra_cells or []),
        ],
    }


def test_select_next_batch_groups_by_endpoint_and_prioritizes():
    from core.coverage import select_next_batch
    out = select_next_batch(_batch_data(), count=10)
    # ep1 (first registered) is the focus; sqli is prioritized over xss within it
    assert out["endpoint_focus"]["path"] == "/login"
    assert [c["injection_type"] for c in out["batch"]] == ["sqli", "xss"]
    assert all(c["endpoint_id"] == "ep1" for c in out["batch"])
    assert out["progress"] == {"endpoint": "0/2", "overall": "0/3"}
    assert out["remaining"] == 3


def test_select_next_batch_count_cap():
    from core.coverage import select_next_batch
    out = select_next_batch(_batch_data(), count=1)
    assert len(out["batch"]) == 1
    assert out["batch"][0]["injection_type"] == "sqli"  # highest priority first


def test_select_next_batch_focuses_started_endpoint():
    # ep2 already has a closed cell → "started" → focus it before opening ep1.
    from core.coverage import select_next_batch
    data = _batch_data(extra_cells=[
        {"id": "c4", "endpoint_id": "ep2", "param": "_endpoint", "param_type": "endpoint",
         "injection_type": "csrf", "status": "tested_clean"},
    ])
    out = select_next_batch(data, count=10)
    assert out["endpoint_focus"]["path"] == "/blog"
    assert out["progress"]["endpoint"] == "1/2"
    assert out["progress"]["overall"] == "1/4"


def test_select_next_batch_empty_when_all_addressed():
    from core.coverage import select_next_batch
    data = _batch_data()
    for c in data["matrix"]:
        c["status"] = "tested_clean"
    out = select_next_batch(data, count=10)
    assert out["batch"] == []
    assert out["endpoint_focus"] is None
    assert out["progress"]["overall"] == "3/3"


@pytest.mark.asyncio
async def test_get_next_batch_async_against_real_matrix(coverage_file):
    await core.coverage.add_endpoint(
        path="/login", method="POST",
        params=[{"name": "username", "type": "body_json", "value_hint": "string"}],
    )
    out = await core.coverage.get_next_batch(count=3)
    assert out["batch"], "expected pending cells for the registered endpoint"
    assert out["endpoint_focus"]["path"] == "/login"
    assert all(c["endpoint_path"] == "/login" for c in out["batch"])


@pytest.mark.asyncio
async def test_coverage_next_batch_handler_enriches_request(coverage_file, monkeypatch):
    import core.coverage as cov
    import core.session as scan_session
    import mcp_server.report_tools as rt
    await cov.add_endpoint(
        path="/login", method="POST",
        params=[{"name": "username", "type": "body_json", "value_hint": "string"}],
    )
    monkeypatch.setattr(scan_session, "get", lambda: {"target": "http://t", "model_profile": "full"})
    out = json.loads(await rt._do_coverage_next_batch({"type": "next_batch"}, cov))
    assert out["batch"]
    assert all(c.get("test_request") for c in out["batch"])  # enriched with a concrete request
    assert "bulk_tested" in out["next_step"]                 # test→close loop guidance present
    assert out["endpoint_focus"]["path"] == "/login"


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

def test_normalize_path_numeric():
    assert core.coverage._normalize_path("/profile/123") == "/profile/{id}"
    assert core.coverage._normalize_path("/api/v2/users/42/posts/7") == "/api/v2/users/{id}/posts/{id}"


def test_normalize_path_uuid():
    assert core.coverage._normalize_path(
        "/item/550e8400-e29b-41d4-a716-446655440000"
    ) == "/item/{id}"


def test_normalize_path_no_change():
    assert core.coverage._normalize_path("/api/users") == "/api/users"
    assert core.coverage._normalize_path("/search") == "/search"


# ---------------------------------------------------------------------------
# in_progress status
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_cell_in_progress(coverage_file):
    await core.coverage.add_endpoint(
        path="/search", method="GET",
        params=[{"name": "q", "type": "query", "value_hint": ""}],
    )
    data = json.loads(coverage_file.read_text())
    cell_id = data["matrix"][0]["id"]
    ok = await core.coverage.update_cell(
        cell_id, "in_progress", notes="Union blocked, trying blind time-based"
    )
    assert ok
    data = json.loads(coverage_file.read_text())
    cell = next(c for c in data["matrix"] if c["id"] == cell_id)
    assert cell["status"] == "in_progress"
    assert "blind time-based" in cell["notes"]
    assert data["meta"]["in_progress"] == 1


@pytest.mark.asyncio
async def test_get_pending_includes_in_progress(coverage_file):
    await core.coverage.add_endpoint(
        path="/test", method="GET",
        params=[{"name": "id", "type": "path", "value_hint": "integer"}],
    )
    data = json.loads(coverage_file.read_text())
    cells = data["matrix"]
    # Mark first cell in_progress
    await core.coverage.update_cell(cells[0]["id"], "in_progress", notes="testing")
    pending = await core.coverage.get_pending()
    ids = [c["id"] for c in pending]
    # Should include the in_progress cell
    assert cells[0]["id"] in ids
    # Should also include remaining pending cells
    assert len(pending) > 1


# ---------------------------------------------------------------------------
# list_cells — compaction-recovery primitive
#
# Smith's context window can be compacted mid-scan, dropping the cell IDs
# it was carrying. list_cells() lets Smith fetch the current matrix with
# joined endpoint context so it can look up the ID it needs and continue
# closing cells without re-registering endpoints (which would create dupes).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_cells_returns_all_with_joined_endpoint_context(coverage_file):
    await core.coverage.add_endpoint(
        path="/login", method="POST",
        params=[{"name": "username", "type": "body", "value_hint": "string"}],
    )
    result = await core.coverage.list_cells()
    assert result["total"] > 0
    assert result["filtered"] == result["total"]
    # Every cell projected has endpoint context joined in
    sample = result["cells"][0]
    assert sample["endpoint_path"] == "/login"
    assert sample["method"] == "POST"
    assert sample["cell_id"].startswith("cell-")
    # Status fields present (default pending for a fresh registration)
    assert sample["status"] == "pending"
    # Compaction-recovery fields: not-yet-tested cells have empty/null values
    # (finding_id is unset → None; tested_by is initialized to ""). Either
    # falsy form means "no test result yet" — Smith reads them as "available
    # for testing" regardless of empty-string vs null.
    assert not sample.get("finding_id")
    assert not sample.get("tested_by")


@pytest.mark.asyncio
async def test_list_cells_filters_by_endpoint_path(coverage_file):
    await core.coverage.add_endpoint(
        path="/login", method="POST",
        params=[{"name": "user", "type": "body", "value_hint": "string"}],
    )
    await core.coverage.add_endpoint(
        path="/api/transfer", method="POST",
        params=[{"name": "amount", "type": "body", "value_hint": "integer"}],
    )
    only_login = await core.coverage.list_cells(endpoint_path="/login")
    assert only_login["filtered"] > 0
    assert all(c["endpoint_path"] == "/login" for c in only_login["cells"])


@pytest.mark.asyncio
async def test_list_cells_filters_by_status(coverage_file):
    await core.coverage.add_endpoint(
        path="/x", method="GET",
        params=[{"name": "q", "type": "query", "value_hint": "string"}],
    )
    data = json.loads(coverage_file.read_text())
    first_id = data["matrix"][0]["id"]
    await core.coverage.update_cell(first_id, "in_progress", notes="testing")

    in_prog = await core.coverage.list_cells(status="in_progress")
    pending = await core.coverage.list_cells(status="pending")
    assert in_prog["filtered"] == 1
    assert pending["filtered"] == len(data["matrix"]) - 1
    assert in_prog["cells"][0]["cell_id"] == first_id


@pytest.mark.asyncio
async def test_list_cells_filters_by_injection_type(coverage_file):
    await core.coverage.add_endpoint(
        path="/echo", method="GET",
        params=[{"name": "msg", "type": "query", "value_hint": "string"}],
    )
    sqli = await core.coverage.list_cells(injection_type="sqli")
    xss  = await core.coverage.list_cells(injection_type="xss")
    assert all(c["injection_type"] == "sqli" for c in sqli["cells"])
    assert all(c["injection_type"] == "xss" for c in xss["cells"])
    # sqli and xss are disjoint sets — no cell shared between them
    sqli_ids = {c["cell_id"] for c in sqli["cells"]}
    xss_ids  = {c["cell_id"] for c in xss["cells"]}
    assert not sqli_ids & xss_ids


@pytest.mark.asyncio
async def test_list_cells_filters_by_param_name(coverage_file):
    await core.coverage.add_endpoint(
        path="/login", method="POST",
        params=[
            {"name": "username", "type": "body", "value_hint": "string"},
            {"name": "password", "type": "body", "value_hint": "string"},
        ],
    )
    pwd_cells = await core.coverage.list_cells(param_name="password")
    user_cells = await core.coverage.list_cells(param_name="user")
    # password param has cells fanned across injection types
    assert all(c["param_name"] == "password" for c in pwd_cells["cells"])
    # 'user' is a substring of 'username' — substring match flags both should miss password
    assert all(c["param_name"] == "username" for c in user_cells["cells"])


@pytest.mark.asyncio
async def test_list_cells_limit_caps_response_size(coverage_file):
    await core.coverage.add_endpoint(
        path="/big", method="POST",
        params=[
            {"name": f"p{i}", "type": "body", "value_hint": "string"}
            for i in range(10)
        ],
    )
    full = await core.coverage.list_cells()
    capped = await core.coverage.list_cells(limit=5)
    # Filtered count is unchanged — limit only truncates the returned slice
    assert capped["filtered"] == full["filtered"]
    assert len(capped["cells"]) == 5


@pytest.mark.asyncio
async def test_list_cells_combined_filters_and_uses(coverage_file):
    """The realistic compaction-recovery case: Smith remembers it was
    testing /login POST password with XSS, lost the cell_id, looks it up."""
    await core.coverage.add_endpoint(
        path="/login", method="POST",
        params=[
            {"name": "username", "type": "body", "value_hint": "string"},
            {"name": "password", "type": "body", "value_hint": "string"},
        ],
    )
    found = await core.coverage.list_cells(
        endpoint_path="/login", method="POST",
        param_name="password", injection_type="xss",
    )
    assert found["filtered"] == 1
    cell = found["cells"][0]
    # Smith now has the cell_id back and can close it
    assert cell["cell_id"].startswith("cell-")
    assert cell["endpoint_path"] == "/login"
    assert cell["param_name"] == "password"
    assert cell["injection_type"] == "xss"


@pytest.mark.asyncio
async def test_list_cells_empty_matrix_returns_empty(coverage_file):
    """Fresh scan, no endpoints registered yet — must not crash."""
    result = await core.coverage.list_cells()
    assert result == {"cells": [], "total": 0, "filtered": 0}
