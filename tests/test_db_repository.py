import json
import sqlite3

import pytest

import core.coverage
import core.findings
import core.session


def _fetch_payload(db_path, run_id: str, kind: str) -> dict:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select payload_json from run_snapshots where run_id = ? and kind = ?",
            (run_id, kind),
        ).fetchone()
    assert row is not None
    return json.loads(row[0])


@pytest.mark.asyncio
async def test_session_findings_coverage_round_trip_by_run_id(
    monkeypatch, tmp_path, findings_file, coverage_file
):
    db_path = tmp_path / "smith.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")

    monkeypatch.setenv("SMITH_RUN_ID", "run-a")
    core.session.start("https://a.example")
    await core.findings.add_finding(
        title="SQLi",
        severity="high",
        target="https://a.example/login",
        description="Login bypass",
        evidence="' OR 1=1--",
    )
    await core.coverage.add_endpoint(
        path="/login",
        method="POST",
        params=[{"name": "username", "type": "body_form", "value_hint": ""}],
    )

    monkeypatch.setenv("SMITH_RUN_ID", "run-b")
    monkeypatch.setattr(core.session, "_current", None)
    core.session.start("https://b.example")
    await core.findings.add_finding(
        title="XSS",
        severity="medium",
        target="https://b.example/search",
        description="Reflected XSS",
        evidence="<script>alert(1)</script>",
    )
    await core.coverage.add_endpoint(
        path="/search",
        method="GET",
        params=[{"name": "q", "type": "query", "value_hint": ""}],
    )

    with sqlite3.connect(db_path) as conn:
        runs = conn.execute(
            "select run_id, target, status from runs order by run_id"
        ).fetchall()

    assert runs == [
        ("run-a", "https://a.example", "running"),
        ("run-b", "https://b.example", "running"),
    ]
    assert _fetch_payload(db_path, "run-a", "findings")["findings"][0]["title"] == "SQLi"
    assert _fetch_payload(db_path, "run-b", "findings")["findings"][0]["title"] == "XSS"
    assert _fetch_payload(db_path, "run-a", "coverage")["endpoints"][0]["path"] == "/login"
    assert _fetch_payload(db_path, "run-b", "coverage")["endpoints"][0]["path"] == "/search"


@pytest.mark.asyncio
async def test_json_cache_survives_db_disabled(monkeypatch, findings_file):
    monkeypatch.delenv("SMITH_DATABASE_URL", raising=False)
    monkeypatch.setenv("SMITH_SINGLE_RUN", "1")

    monkeypatch.setenv("SMITH_RUN_ID", "run-a")
    await core.findings.add_finding(
        title="SQLi",
        severity="high",
        target="https://a.example/login",
        description="Login bypass",
        evidence="' OR 1=1--",
    )

    monkeypatch.setenv("SMITH_RUN_ID", "run-b")

    data = core.findings._load()

    assert data["findings"][0]["title"] == "SQLi"


@pytest.mark.asyncio
async def test_db_error_does_not_truncate_cache(monkeypatch, findings_file):
    monkeypatch.setenv("SMITH_DATABASE_URL", "postgresql+nosuchdriver://broken")
    monkeypatch.setenv("SMITH_RUN_ID", "run-a")

    await core.findings.add_finding(
        title="XSS",
        severity="medium",
        target="https://example.test/search",
        description="Reflected XSS",
        evidence="<script>alert(1)</script>",
    )

    monkeypatch.setenv("SMITH_RUN_ID", "run-b")

    data = core.findings._load()

    assert data["findings"][0]["title"] == "XSS"
