import json
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

import core.api_server as api_server
from core import paths as core_paths
import core.steering as steering_store
import core.wishlist as wishlist_store
from core.api_server import app
from core import dashboard_auth
from core import db as db_store


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_run(client: TestClient, operator_token: str, target: str) -> dict:
    with patch("subprocess.Popen", return_value=MagicMock(pid=1234)):
        response = client.post(
            "/api/runs",
            json={"target": target, "depth": "recon"},
            headers=_headers(operator_token),
        )
    assert response.status_code == 200
    return response.json()


def _write_event_stream(events_dir, session_id: str, target: str, message: str) -> None:
    events_dir.mkdir(parents=True, exist_ok=True)
    (events_dir / f"{session_id}.jsonl").write_text(
        json.dumps({
            "event_id": f"evt-{session_id}",
            "event_type": "note",
            "sequence": 1,
            "occurred_at": "2026-01-01T00:00:00Z",
            "note": {"message": message},
        }) + "\n",
        encoding="utf-8",
    )
    bundle = events_dir / session_id
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "meta.json").write_text(
        json.dumps({"target": target, "started": "2026-01-01T00:00:00Z"}),
        encoding="utf-8",
    )


def test_operator_token_can_create_and_stop(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()

    created = _create_run(client, operator_token, "https://a.example")
    listed = client.get("/api/runs", headers=_headers(operator_token))
    stopped = client.post(f"/api/runs/{created['run_id']}/stop", headers=_headers(operator_token))

    assert created["status"] == "running"
    assert created["token"]
    assert "#k=" in created["dashboard_url"]
    assert listed.status_code == 200
    assert listed.json()[0]["run_id"] == created["run_id"]
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"


def test_run_token_scopes_sessions_and_session_log_to_run_workdir(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    global_events = tmp_path / "global" / "logs" / "smith-events"
    _write_event_stream(global_events, "sess-a", "https://global-a.example", "GLOBAL A LEAK")
    _write_event_stream(global_events, "sess-b", "https://global-b.example", "GLOBAL B LEAK")
    monkeypatch.setattr(core_paths, "SMITH_EVENTS_DIR", global_events)
    monkeypatch.setattr(core_paths, "SESSION_FILE", tmp_path / "global" / "session.json")
    core_paths.SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    core_paths.SESSION_FILE.write_text(json.dumps({"id": "sess-b", "status": "running"}))

    run_a_workdir = tmp_path / "runs" / "run-a"
    run_b_workdir = tmp_path / "runs" / "run-b"
    _write_event_stream(run_a_workdir / "logs" / "smith-events", "sess-a", "https://a.example", "RUN A ONLY")
    _write_event_stream(run_b_workdir / "logs" / "smith-events", "sess-b", "https://b.example", "RUN B ONLY")
    (run_a_workdir / "session.json").write_text(json.dumps({"id": "sess-a", "status": "running"}))
    (run_b_workdir / "session.json").write_text(json.dumps({"id": "sess-b", "status": "running"}))

    repo = db_store.get_repository()
    repo.upsert_run("run-a", {"run_id": "run-a", "target": "https://a.example", "status": "running"}, str(run_a_workdir))
    repo.upsert_run("run-b", {"run_id": "run-b", "target": "https://b.example", "status": "running"}, str(run_b_workdir))
    token_a = dashboard_auth.mint_run_token("run-a")
    client = TestClient(app)

    sessions = client.get("/api/sessions", headers=_headers(token_a))
    log_a = client.get("/api/session-log", headers=_headers(token_a))
    log_b = client.get("/api/session-log?session=sess-b", headers=_headers(token_a))

    assert sessions.status_code == 200
    assert [row["id"] for row in sessions.json()["sessions"]] == ["sess-a"]
    assert log_a.status_code == 200
    assert [row["id"] for row in log_a.json()["sessions"]] == ["sess-a"]
    assert log_a.json()["events"][0]["payload"]["message"] == "RUN A ONLY"
    assert log_b.status_code == 403


def test_api_runs_list_persists_after_restart(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    operator_token = dashboard_auth.mint_operator_token()
    first_client = TestClient(app)
    created = _create_run(first_client, operator_token, "https://persist.example")

    second_client = TestClient(app)
    listed = second_client.get("/api/runs", headers=_headers(operator_token))

    assert listed.status_code == 200
    assert [row["run_id"] for row in listed.json()] == [created["run_id"]]


def test_run_token_scopes_existing_tabs(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    run_a = _create_run(client, operator_token, "https://a.example")
    run_b = _create_run(client, operator_token, "https://b.example")

    repo = db_store.get_repository()
    repo.save_snapshot(run_a["run_id"], "findings", {"findings": [{"title": "SQLi A"}]})
    repo.save_snapshot(run_a["run_id"], "session", {"target": "https://a.example", "status": "running"})
    repo.save_snapshot(run_b["run_id"], "findings", {"findings": [{"title": "XSS B"}]})
    repo.save_snapshot(run_b["run_id"], "session", {"target": "https://b.example", "status": "running"})

    findings_a = client.get("/api/findings", headers=_headers(run_a["token"]))
    session_b = client.get("/api/session", headers=_headers(run_b["token"]))

    assert findings_a.json()["findings"][0]["title"] == "SQLi A"
    assert session_b.json()["target"] == "https://b.example"


def test_operator_can_mint_persisted_run_token_that_scopes_existing_tabs(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    global_findings = tmp_path / "findings.json"
    global_session = tmp_path / "session.json"
    global_cost = tmp_path / "session_cost.json"
    global_coverage = tmp_path / "coverage.json"
    global_findings.write_text(json.dumps({"findings": [{"title": "GLOBAL"}]}))
    global_session.write_text(json.dumps({"target": "https://global.example"}))
    global_cost.write_text(json.dumps({"total_usd": 99}))
    global_coverage.write_text(json.dumps({"endpoints": [{"path": "/global"}], "cells": []}))
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(api_server, "_FINDINGS_FILE", global_findings)
    monkeypatch.setattr(api_server, "_SESSION_FILE", global_session)
    monkeypatch.setattr(api_server, "_COST_FILE", global_cost)
    monkeypatch.setattr(api_server, "_COVERAGE_FILE", global_coverage)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    repo = db_store.get_repository()
    repo.upsert_run("run-a", {"run_id": "run-a", "target": "https://a.example", "status": "running"}, str(tmp_path / "run-a"))
    repo.upsert_run("run-b", {"run_id": "run-b", "target": "https://b.example", "status": "running"}, str(tmp_path / "run-b"))
    repo.save_snapshot("run-a", "findings", {"findings": [{"title": "SQLi A"}]})
    repo.save_snapshot("run-a", "session", {"target": "https://a.example", "status": "running"})
    repo.save_snapshot("run-a", "coverage", {"endpoints": [{"path": "/a"}], "cells": []})
    repo.save_snapshot("run-a", "cost", {"total_usd": 1})
    repo.save_snapshot("run-b", "findings", {"findings": [{"title": "XSS B"}]})
    repo.save_snapshot("run-b", "session", {"target": "https://b.example", "status": "running"})
    repo.save_snapshot("run-b", "coverage", {"endpoints": [{"path": "/b"}], "cells": []})
    repo.save_snapshot("run-b", "cost", {"total_usd": 2})

    minted = client.post("/api/runs/run-a/token", headers=_headers(operator_token))
    assert minted.status_code == 200
    selected_token = minted.json()["token"]
    cross_mint = client.post("/api/runs/run-b/token", headers=_headers(selected_token))
    missing = client.post("/api/runs/missing/token", headers=_headers(operator_token))

    findings = client.get("/api/findings", headers=_headers(selected_token))
    session = client.get("/api/session", headers=_headers(selected_token))
    coverage = client.get("/api/coverage", headers=_headers(selected_token))
    cost = client.get("/api/cost", headers=_headers(selected_token))

    assert cross_mint.status_code == 403
    assert missing.status_code == 404
    assert findings.json()["findings"][0]["title"] == "SQLi A"
    assert session.json()["target"] == "https://a.example"
    assert coverage.json()["endpoints"] == [{"path": "/a"}]
    assert cost.json()["total_usd"] == 1


def test_cross_run_token_rejected(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    run_a = _create_run(client, operator_token, "https://a.example")
    run_b = _create_run(client, operator_token, "https://b.example")

    response = client.post(f"/api/runs/{run_b['run_id']}/stop", headers=_headers(run_a["token"]))

    assert response.status_code == 403


def test_create_run_masks_runtime_errors(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    with patch("control_plane.orchestrator.create_run", side_effect=RuntimeError("traceback details")):
        response = client.post(
            "/api/runs",
            json={"target": "https://a.example", "depth": "recon"},
            headers=_headers(operator_token),
        )

    assert response.status_code == 503
    assert response.json() == {"error": "service unavailable"}


def test_mint_run_token_masks_runtime_errors(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    with patch("control_plane.orchestrator.mint_existing_run_token", side_effect=RuntimeError("traceback details")):
        response = client.post("/api/runs/run-a/token", headers=_headers(operator_token))

    assert response.status_code == 503
    assert response.json() == {"error": "service unavailable"}


def test_stop_run_masks_runtime_errors(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    with patch("control_plane.orchestrator.stop_run", side_effect=RuntimeError("traceback details")):
        response = client.post("/api/runs/run-a/stop", headers=_headers(operator_token))

    assert response.status_code == 503
    assert response.json() == {"error": "service unavailable"}


def test_run_token_scopes_finding_detail_patch_and_delete(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    client = TestClient(app)
    operator_token = dashboard_auth.mint_operator_token()
    run_a = _create_run(client, operator_token, "https://a.example")
    run_b = _create_run(client, operator_token, "https://b.example")

    finding_a = {"id": "finding-a", "title": "SQLi A", "severity": "high"}
    finding_b = {"id": "finding-a", "title": "SQLi B", "severity": "medium"}
    repo = db_store.get_repository()
    repo.save_snapshot(run_a["run_id"], "findings", {"findings": [finding_a], "archived": [], "chains": [], "meta": {}})
    repo.save_snapshot(run_b["run_id"], "findings", {"findings": [finding_b], "archived": [], "chains": [], "meta": {}})

    detail = client.get(f"/api/findings/{finding_a['id']}", headers=_headers(run_a["token"]))
    patched = client.patch(
        f"/api/findings/{finding_a['id']}",
        json={"title": "SQLi A fixed scope"},
        headers=_headers(run_a["token"]),
    )
    deleted = client.delete(f"/api/findings/{finding_a['id']}", headers=_headers(run_a["token"]))

    run_a_snapshot = repo.load_snapshot(run_a["run_id"], "findings")
    run_b_snapshot = repo.load_snapshot(run_b["run_id"], "findings")

    assert detail.status_code == 200
    assert detail.json()["finding"]["title"] == "SQLi A"
    assert patched.status_code == 200
    assert patched.json() == {"ok": True}
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert run_a_snapshot["findings"] == []
    assert run_a_snapshot["archived"][0]["title"] == "SQLi A fixed scope"
    assert run_b_snapshot["findings"][0]["title"] == "SQLi B"


def test_run_token_without_snapshot_does_not_fallback_to_global_findings(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    global_findings = tmp_path / "findings.json"
    global_findings.write_text(json.dumps({
        "findings": [{"id": "global", "title": "GLOBAL LEAK"}],
        "diagrams": [],
        "chains": [],
        "meta": {},
    }))
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(api_server, "_FINDINGS_FILE", global_findings)

    token = dashboard_auth.mint_run_token("run-a")
    response = TestClient(app).get("/api/findings", headers=_headers(token))

    assert response.status_code == 200
    assert response.json().get("findings") == []


def test_run_token_scopes_wishlist_qa_and_steering_reads(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(wishlist_store, "_WISHLIST_FILE", tmp_path / "wishlist_queue.json")
    monkeypatch.setattr(steering_store, "_STEERING_FILE", tmp_path / "steering_queue.json")
    monkeypatch.setattr(api_server, "_QA_STATE_FILE", tmp_path / "qa_state.json")
    monkeypatch.setattr(api_server, "_STEERING_FILE", tmp_path / "steering_queue.json")
    wishlist_store._WISHLIST_FILE.write_text(json.dumps({"items": [{"need": "GLOBAL"}]}))
    steering_store._STEERING_FILE.write_text(json.dumps({"directives": [{"message": "GLOBAL"}]}))
    api_server._QA_STATE_FILE.write_text(json.dumps({"alerts": [{"message": "GLOBAL"}]}))

    token_a = dashboard_auth.mint_run_token("run-a")
    repo = db_store.get_repository()
    repo.save_snapshot("run-a", "wishlist", {"items": [{"id": "wish-a", "need": "A"}]})
    repo.save_snapshot("run-a", "qa", {"alerts": [{"message": "QA A"}]})
    repo.save_snapshot("run-a", "steering", {"directives": [{"id": "steer-a", "message": "STEER A"}]})
    repo.save_snapshot("run-b", "wishlist", {"items": [{"id": "wish-b", "need": "B"}]})
    repo.save_snapshot("run-b", "qa", {"alerts": [{"message": "QA B"}]})
    repo.save_snapshot("run-b", "steering", {"directives": [{"id": "steer-b", "message": "STEER B"}]})

    client = TestClient(app)
    wishlist = client.get("/api/wishlist", headers=_headers(token_a))
    qa = client.get("/api/qa", headers=_headers(token_a))
    steering = client.get("/api/steering", headers=_headers(token_a))

    assert wishlist.json()["items"] == [{"id": "wish-a", "need": "A"}]
    assert qa.json()["alerts"] == [{"message": "QA A"}]
    assert steering.json()["directives"] == [{"id": "steer-a", "message": "STEER A"}]


def test_run_token_steer_writes_only_authenticated_run(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(steering_store, "_STEERING_FILE", tmp_path / "steering_queue.json")

    token_a = dashboard_auth.mint_run_token("run-a")
    response = TestClient(app).post(
        "/api/steer",
        json={"message": "stay in run a"},
        headers=_headers(token_a),
    )

    repo = db_store.get_repository()
    run_a = repo.load_snapshot("run-a", "steering")
    run_b = repo.load_snapshot("run-b", "steering")
    assert response.status_code == 200
    assert run_a["directives"][0]["message"] == "HUMAN INSTRUCTION: stay in run a"
    assert run_b is None
    assert not steering_store._STEERING_FILE.exists()


def test_run_token_wishlist_fulfill_updates_only_authenticated_run(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(wishlist_store, "_WISHLIST_FILE", tmp_path / "wishlist_queue.json")
    monkeypatch.setattr(steering_store, "_STEERING_FILE", tmp_path / "steering_queue.json")

    token_a = dashboard_auth.mint_run_token("run-a")
    repo = db_store.get_repository()
    open_item = {
        "id": "wish-shared",
        "need": "creds",
        "status": "open",
        "blocking_cell_ids": ["cell-a"],
    }
    repo.save_snapshot("run-a", "wishlist", {"items": [dict(open_item)]})
    repo.save_snapshot("run-b", "wishlist", {"items": [dict(open_item)]})

    response = TestClient(app).post(
        "/api/wishlist/wish-shared/fulfill",
        json={"note": "use creds"},
        headers=_headers(token_a),
    )

    run_a_wishlist = repo.load_snapshot("run-a", "wishlist")
    run_b_wishlist = repo.load_snapshot("run-b", "wishlist")
    run_a_steering = repo.load_snapshot("run-a", "steering")
    assert response.status_code == 200
    assert run_a_wishlist["items"][0]["status"] == "fulfilled"
    assert run_b_wishlist["items"][0]["status"] == "open"
    assert "WISHLIST FULFILLED" in run_a_steering["directives"][0]["message"]


def test_run_token_triage_start_and_cancel_update_only_authenticated_run(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setattr(steering_store, "_STEERING_FILE", tmp_path / "steering_queue.json")

    token_a = dashboard_auth.mint_run_token("run-a")
    repo = db_store.get_repository()
    repo.save_snapshot("run-a", "session", {"run_id": "run-a", "target": "https://a.example", "status": "running"})
    repo.save_snapshot("run-b", "session", {"run_id": "run-b", "target": "https://b.example", "status": "running"})
    repo.save_snapshot("run-a", "findings", {"findings": [{"id": "finding-a"}]})
    repo.save_snapshot("run-b", "findings", {"findings": [{"id": "finding-b"}]})

    client = TestClient(app)
    with (
        patch("core.adjunction.pending_findings", return_value=[{"id": "finding-a"}]),
        patch("core.adjunction.directive.build_adjudication_directive", return_value="ADJUDICATE A"),
        patch("core.adjunction.log.log_directive"),
    ):
        started = client.post("/api/triage", headers=_headers(token_a))
    cancelled = client.post("/api/triage-cancel", headers=_headers(token_a))

    run_a_session = repo.load_snapshot("run-a", "session")
    run_b_session = repo.load_snapshot("run-b", "session")
    run_a_steering = repo.load_snapshot("run-a", "steering")
    run_b_steering = repo.load_snapshot("run-b", "steering")
    assert started.status_code == 200
    assert started.json()["status"] == "triaging"
    assert cancelled.status_code == 200
    assert run_a_session["triage_requested"] is False
    assert "triage_requested" not in run_b_session
    assert run_a_steering["directives"][0]["status"] == "acknowledged"
    assert run_b_steering is None
    assert not steering_store._STEERING_FILE.exists()


def test_run_token_session_triage_self_heal_uses_run_snapshots_only(monkeypatch, tmp_path):
    db_path = tmp_path / "runs.db"
    global_findings = tmp_path / "findings.json"
    global_findings.write_text(json.dumps({
        "findings": [{"id": "global", "severity": "high", "title": "GLOBAL PENDING"}],
        "diagrams": [],
        "chains": [],
        "meta": {},
    }))
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    import core.findings as findings_store

    monkeypatch.setattr(findings_store, "FINDINGS_FILE", global_findings)
    monkeypatch.setattr(steering_store, "_STEERING_FILE", tmp_path / "steering_queue.json")

    token_a = dashboard_auth.mint_run_token("run-a")
    repo = db_store.get_repository()
    repo.save_snapshot("run-a", "session", {
        "run_id": "run-a",
        "target": "https://a.example",
        "status": "running",
        "triage_requested": True,
    })
    repo.save_snapshot("run-a", "findings", {
        "findings": [{
            "id": "finding-a",
            "severity": "high",
            "adjudication": {"reproducible": False, "rationale": "reviewed"},
        }],
    })
    repo.save_snapshot("run-a", "steering", {
        "directives": [{
            "id": "steer-a",
            "ts": "now",
            "code": "RESUME_REQUIRED",
            "priority": "high",
            "message": "triage",
            "skill": None,
            "trigger": "TRIAGE_ADJUDICATION",
            "status": "pending",
        }]
    })
    repo.save_snapshot("run-b", "session", {
        "run_id": "run-b",
        "target": "https://b.example",
        "status": "running",
        "triage_requested": True,
    })

    response = TestClient(app).get("/api/session", headers=_headers(token_a))

    run_a_session = repo.load_snapshot("run-a", "session")
    run_b_session = repo.load_snapshot("run-b", "session")
    run_a_steering = repo.load_snapshot("run-a", "steering")
    assert response.status_code == 200
    assert response.json()["target"] == "https://a.example"
    assert response.json()["pending_adjudication"] == 0
    assert "triage_requested" not in run_a_session
    assert run_b_session["triage_requested"] is True
    assert run_a_steering["directives"][0]["status"] == "acknowledged"
    assert not steering_store._STEERING_FILE.exists()
