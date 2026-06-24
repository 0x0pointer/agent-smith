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
