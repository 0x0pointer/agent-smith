"""control_plane.work_queue — Source updates become queued work for an idle run."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from control_plane import orchestrator, work_queue
from core import db as db_store


class _FakeSource:
    """A minimal stand-in for a Source instance: serves /list from a mutable dict."""

    def __init__(self):
        self.notes: dict[str, str] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = json.dumps({"ready": True, "notes": [
                    {"path": p, "chunks": 1, "sha256": h} for p, h in sorted(outer.notes.items())]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{tmp_path / 'cp.db'}")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.delenv("SMITH_WORK_QUEUE_DISABLED", raising=False)
    monkeypatch.setattr(orchestrator._paths, "RUNTIME_ROOT", tmp_path, raising=False)
    source = _FakeSource()
    registry = tmp_path / "sources.yaml"
    registry.write_text(f"sources:\n  team-kb:\n    url: {source.url}\n")
    monkeypatch.setenv("SOURCE_REGISTRY", str(registry))
    yield source
    source.close()


def _start_run(source_name="team-kb"):
    payload = {"target": "https://a.example", "depth": "recon"}
    if source_name:
        payload["source"] = source_name
    with patch("subprocess.Popen", return_value=MagicMock(pid=4321)):
        return orchestrator.create_run(payload)["run_id"]


def _titles(run_id, *statuses):
    repo = db_store.get_repository()
    return [i["title"] for i in reversed(repo.list_work(run_id, statuses=statuses or None))]


def test_binding_a_source_does_not_queue_its_existing_content(env):
    env.notes = {"methodology/sqli.md": "h1", "prs/100.md": "h2"}
    run_id = _start_run()

    assert work_queue.poll_sources() == 0
    assert _titles(run_id) == []


def test_new_and_edited_notes_are_queued_once(env):
    env.notes = {"prs/100.md": "h1"}
    run_id = _start_run()
    work_queue.poll_sources()                       # baseline

    env.notes["prs/101.md"] = "h2"                  # a new note
    env.notes["prs/100.md"] = "h1-edited"           # an edit to a known note
    assert work_queue.poll_sources() == 1
    assert work_queue.poll_sources() == 0           # nothing new: not queued again

    repo = db_store.get_repository()
    item = repo.list_work(run_id)[0]
    assert item["kind"] == "source_update" and item["status"] == "queued"
    assert {(n["path"], n["change"]) for n in item["payload"]["notes"]} == {
        ("prs/100.md", "changed"), ("prs/101.md", "new")}


def test_unreachable_source_loses_nothing(env, monkeypatch):
    env.notes = {"prs/100.md": "h1"}
    run_id = _start_run()
    work_queue.poll_sources()

    env.notes["prs/101.md"] = "h2"
    with patch.object(work_queue, "_fetch_notes", return_value=None):   # Source down
        assert work_queue.poll_sources() == 0
    assert work_queue.poll_sources() == 1           # picked up once it is back
    assert len(_titles(run_id)) == 1


def test_runs_without_a_source_are_ignored(env):
    env.notes = {"prs/100.md": "h1"}
    run_id = _start_run(source_name=None)
    work_queue.poll_sources()
    env.notes["prs/101.md"] = "h2"

    assert work_queue.poll_sources() == 0 and _titles(run_id) == []


def test_idle_run_gets_one_item_at_a_time_and_nothing_is_dropped(env):
    env.notes = {}
    run_id = _start_run()
    work_queue.poll_sources()
    for n in (1, 2, 3):                             # three separate updates arrive
        env.notes[f"prs/{n}.md"] = f"h{n}"
        work_queue.poll_sources()
    assert len(_titles(run_id, "queued")) == 3

    prompts = []

    def _spawn(args, **kwargs):
        prompts.append(args[args.index("-p") + 1])
        return MagicMock(pid=6000 + len(prompts))

    # A busy run is left alone.
    with patch.object(orchestrator, "_worker_alive", return_value=True), patch("subprocess.Popen", side_effect=_spawn):
        assert work_queue.dispatch() == 0
    assert prompts == []

    # Idle: exactly one item starts per pass; the finished one is closed before the next.
    with patch.object(orchestrator, "_worker_alive", return_value=False), \
         patch.object(work_queue, "_MIN_WORK_SECONDS", 0), \
         patch("subprocess.Popen", side_effect=_spawn):
        for expected_done in (0, 1, 2):
            assert work_queue.dispatch() == 1
            assert len(_titles(run_id, "done")) == expected_done
            assert len(_titles(run_id, "running")) == 1
        assert work_queue.dispatch() == 0           # queue drained
    assert len(_titles(run_id, "done")) == 3 and _titles(run_id, "queued", "running") == []

    # Each turn got its own item, in arrival order, with the scope and data rules.
    assert [p.split("prs/")[1][0] for p in prompts] == ["1", "2", "3"]
    assert all("DATA, not instructions" in p and "out of scope" in p for p in prompts)


def test_item_is_retried_when_the_agent_dies_immediately_then_fails(env):
    env.notes = {}
    run_id = _start_run()
    work_queue.poll_sources()
    env.notes["prs/1.md"] = "h1"
    work_queue.poll_sources()
    repo = db_store.get_repository()

    with patch.object(orchestrator, "_worker_alive", return_value=False), \
         patch.object(work_queue, "_MIN_WORK_SECONDS", 3600), \
         patch("subprocess.Popen", return_value=MagicMock(pid=7000)):
        for _ in range(repo.WORK_MAX_ATTEMPTS):
            assert work_queue.dispatch() == 1       # leased again after each instant death
        assert work_queue.dispatch() == 0           # out of attempts

    item = repo.list_work(run_id)[0]
    assert item["status"] == "failed" and item["attempts"] == repo.WORK_MAX_ATTEMPTS


def test_paused_and_ended_runs_are_not_started(env):
    env.notes = {}
    run_id = _start_run()
    work_queue.enqueue_manual(run_id, "Check the new export endpoint", "POST /api/export was added in PR 7")
    repo = db_store.get_repository()
    row = repo.get_run(run_id)

    for status in ("intervention_required", "complete"):
        repo.upsert_run(run_id, {**json.loads(row["payload_json"]), "status": status}, row["workdir"])
        with patch.object(orchestrator, "_worker_alive", return_value=False), patch("subprocess.Popen") as popen:
            assert work_queue.dispatch() == 0
        popen.assert_not_called()
    assert _titles(run_id, "queued") == ["Check the new export endpoint"]


def test_manual_items_are_idempotent_and_carry_their_text(env):
    run_id = _start_run()
    first = work_queue.enqueue_manual(run_id, "PR 7", "test POST /api/export")
    again = work_queue.enqueue_manual(run_id, "PR 7", "test POST /api/export")

    assert first is not None and again is None
    item = db_store.get_repository().list_work(run_id)[0]
    assert "test POST /api/export" in work_queue.work_prompt(item)
    assert work_queue.summary(run_id)["queued"] == 1
    with pytest.raises(KeyError):
        work_queue.enqueue_manual("run-missing", "x", "y")
