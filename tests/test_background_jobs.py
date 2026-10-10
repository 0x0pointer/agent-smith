"""
Tests for PR-F — background/async execution of long-running tools.

Covers:
  * JobRegistry lifecycle: submit → running → done (result + hoisted artifact_id)
  * poll of an unknown / missing job id
  * disk persistence + reload (reconstruct a job from logs/jobs/<id>.json)
  * concurrency cap (reject beyond the limit, with a reason)
  * job_list listing + status filter
  * kali(background=True) returns immediately and defers the real work
  * scan(background=True) returns immediately and defers the real work
  * the session() action router wires job_poll / job_list

All work coroutines are in-memory fakes — no kali/docker/subprocess is executed,
and logs/jobs is redirected to a tmp dir so nothing touches real runtime state.
"""
import asyncio
import json

import pytest
from unittest.mock import patch

import mcp_server.jobs as jobs
import mcp_server.kali_tools as kali_tools
import mcp_server.scan_tools as scan_tools
import mcp_server.session_tools as session_tools


@pytest.fixture(autouse=True)
def _isolate_jobs(tmp_path, monkeypatch):
    """Redirect the on-disk job store to tmp and reset the in-memory registry."""
    monkeypatch.setattr(jobs, "_JOBS_DIR", tmp_path / "jobs")
    monkeypatch.delenv("SMITH_MAX_BACKGROUND_JOBS", raising=False)
    jobs.reset()
    yield
    jobs.reset()


def _envelope(summary="done", artifact="art_000_abcdef12"):
    """A canned envelope string, shaped like what wrap() returns."""
    return json.dumps({"summary": summary, "facts": [], "evidence": {}, "artifact": artifact})


# ---------------------------------------------------------------------------
# Registry lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lifecycle_running_then_done():
    gate = asyncio.Event()

    async def work():
        await gate.wait()
        return _envelope(summary="scan complete", artifact="nuclei_12_deadbeef")

    start = json.loads(jobs.submit("kali", {"command": "hydra ..."}, work))
    assert start["status"] == "running"
    job_id = start["job_id"]
    assert "job_poll" in start["poll_with"]
    tasks = list(jobs._JOB_TASKS)

    # Still running while the gate is closed.
    poll = json.loads(jobs.poll_response({"job_id": job_id}))
    assert poll["status"] == "running"
    assert poll["job_id"] == job_id
    assert "elapsed_seconds" in poll

    # Release and let the task finish.
    gate.set()
    await asyncio.gather(*tasks)

    done = json.loads(jobs.poll_response({"job_id": job_id}))
    assert done["status"] == "done"
    # The full sync-equivalent envelope is delivered under result …
    assert done["result"]["summary"] == "scan complete"
    # … and the real artifact_id is hoisted for convenience.
    assert done["artifact_id"] == "nuclei_12_deadbeef"
    assert done["elapsed_seconds"] >= 0


@pytest.mark.asyncio
async def test_job_error_is_captured():
    async def work():
        raise RuntimeError("boom")

    start = json.loads(jobs.submit("kali", {"command": "x"}, work))
    await asyncio.gather(*list(jobs._JOB_TASKS))
    poll = json.loads(jobs.poll_response({"job_id": start["job_id"]}))
    assert poll["status"] == "error"
    assert "RuntimeError: boom" in poll["error"]


# ---------------------------------------------------------------------------
# Unknown / missing id
# ---------------------------------------------------------------------------

def test_poll_unknown_id():
    resp = json.loads(jobs.poll_response({"job_id": "does_not_exist"}))
    assert resp["status"] == "unknown"
    assert resp["job_id"] == "does_not_exist"


def test_poll_missing_id():
    resp = json.loads(jobs.poll_response({}))
    assert resp["status"] == "error"
    assert "job_id" in resp["error"]


# ---------------------------------------------------------------------------
# Disk persistence + reload
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disk_persistence_and_reload():
    async def work():
        return _envelope(artifact="ffuf_55_cafebabe")

    start = json.loads(jobs.submit("scan:ffuf", {"target": "http://t"}, work))
    job_id = start["job_id"]
    await asyncio.gather(*list(jobs._JOB_TASKS))

    # The record is persisted one-file-per-job under the redirected logs/jobs dir.
    on_disk = jobs._JOBS_DIR / f"{job_id}.json"
    assert on_disk.exists()
    disk_rec = json.loads(on_disk.read_text())
    assert disk_rec["status"] == "done"
    assert disk_rec["artifact_id"] == "ffuf_55_cafebabe"

    # Simulate a later MCP call that lost the in-memory registry (compaction /
    # reload): get() must reconstruct the job from disk.
    jobs._REGISTRY.clear()
    assert job_id not in jobs._REGISTRY
    reloaded = jobs.get(job_id)
    assert reloaded is not None
    assert reloaded["status"] == "done"

    # And a poll after the in-memory loss still returns the full result.
    jobs._REGISTRY.clear()
    done = json.loads(jobs.poll_response({"job_id": job_id}))
    assert done["status"] == "done"
    assert done["artifact_id"] == "ffuf_55_cafebabe"


# ---------------------------------------------------------------------------
# Concurrency cap
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrency_cap_rejects_beyond_limit(monkeypatch):
    monkeypatch.setattr(jobs, "_MAX_CONCURRENT_JOBS", 2)
    gate = asyncio.Event()

    async def blocker():
        await gate.wait()
        return _envelope()

    r1 = json.loads(jobs.submit("kali", {"command": "1"}, blocker))
    r2 = json.loads(jobs.submit("kali", {"command": "2"}, blocker))
    assert r1["status"] == "running"
    assert r2["status"] == "running"

    # Third submission exceeds the cap → rejected with a reason, no task created.
    r3 = json.loads(jobs.submit("kali", {"command": "3"}, blocker))
    assert r3["status"] == "rejected"
    assert r3["max_concurrent"] == 2
    assert r3["running"] == 2
    assert "cap" in r3["reason"].lower()

    # Drain the two running jobs, then capacity frees up.
    gate.set()
    await asyncio.gather(*list(jobs._JOB_TASKS))
    assert jobs._running_count() == 0
    r4 = json.loads(jobs.submit("kali", {"command": "4"}, _done_now))
    assert r4["status"] == "running"
    await asyncio.gather(*list(jobs._JOB_TASKS))


async def _done_now():
    return _envelope()


def test_env_overrides_concurrency_cap(monkeypatch):
    monkeypatch.setattr(jobs, "_MAX_CONCURRENT_JOBS", 4)
    monkeypatch.setenv("SMITH_MAX_BACKGROUND_JOBS", "7")
    assert jobs._max_concurrent() == 7
    monkeypatch.setenv("SMITH_MAX_BACKGROUND_JOBS", "not-a-number")
    assert jobs._max_concurrent() == 4  # falls back to the module default


# ---------------------------------------------------------------------------
# job_list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_job_list_and_status_filter():
    gate = asyncio.Event()

    async def blocker():
        await gate.wait()
        return _envelope()

    async def quick():
        return _envelope(artifact="q_1_2")

    running = json.loads(jobs.submit("kali", {"command": "slow"}, blocker))
    done = json.loads(jobs.submit("scan:nuclei", {"target": "t"}, quick))
    # Let the quick one finish while the blocker stays running.
    await asyncio.sleep(0)
    for _ in range(5):
        if jobs.get(done["job_id"]).get("status") == "done":
            break
        await asyncio.sleep(0.01)

    listing = json.loads(jobs.list_response({}))
    ids = {j["job_id"] for j in listing["jobs"]}
    assert running["job_id"] in ids and done["job_id"] in ids
    assert listing["running"] == 1

    only_running = json.loads(jobs.list_response({"status": "running"}))
    assert [j["job_id"] for j in only_running["jobs"]] == [running["job_id"]]

    gate.set()
    await asyncio.gather(*list(jobs._JOB_TASKS))


# ---------------------------------------------------------------------------
# kali(background=True) wiring
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kali_background_returns_immediately(monkeypatch):
    gate = asyncio.Event()

    async def fake_core(command, timeout):
        await gate.wait()
        return _envelope(summary="kali bg done", artifact="kali_9_9")

    monkeypatch.setattr(kali_tools, "_kali_run_and_wrap", fake_core)

    with patch.object(kali_tools, "scan_session") as msess, \
         patch.object(kali_tools, "cost_tracker") as mcost:
        msess.check_limits.return_value = None
        mcost.get_summary.return_value = {}
        resp = json.loads(await kali_tools.kali("hydra -L users -P pass ssh://t", background=True))

    assert resp["status"] == "running"
    job_id = resp["job_id"]
    tasks = list(jobs._JOB_TASKS)

    # Deferred: the work has NOT produced a result yet.
    assert json.loads(jobs.poll_response({"job_id": job_id}))["status"] == "running"

    gate.set()
    await asyncio.gather(*tasks)
    done = json.loads(jobs.poll_response({"job_id": job_id}))
    assert done["status"] == "done"
    assert done["artifact_id"] == "kali_9_9"
    assert done["result"]["summary"] == "kali bg done"


@pytest.mark.asyncio
async def test_kali_sync_path_unchanged(monkeypatch):
    """background omitted → the synchronous core is awaited inline (no job created)."""
    async def fake_core(command, timeout):
        return _envelope(summary="sync")

    monkeypatch.setattr(kali_tools, "_kali_run_and_wrap", fake_core)
    with patch.object(kali_tools, "scan_session") as msess, \
         patch.object(kali_tools, "cost_tracker") as mcost:
        msess.check_limits.return_value = None
        mcost.get_summary.return_value = {}
        resp = json.loads(await kali_tools.kali("id"))

    assert resp["summary"] == "sync"
    assert jobs._running_count() == 0
    assert list(jobs._JOB_TASKS) == []


@pytest.mark.asyncio
async def test_kali_background_respects_limit(monkeypatch):
    """A hit limit short-circuits BEFORE a job is ever submitted."""
    with patch.object(kali_tools, "scan_session") as msess, \
         patch.object(kali_tools, "cost_tracker") as mcost:
        msess.check_limits.return_value = "LIMIT HIT: cost exceeded"
        mcost.get_summary.return_value = {}
        resp = await kali_tools.kali("hydra ...", background=True)

    assert resp == "LIMIT HIT: cost exceeded"
    assert list(jobs._JOB_TASKS) == []


# ---------------------------------------------------------------------------
# scan(background=True) wiring
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_background_returns_immediately(monkeypatch):
    gate = asyncio.Event()

    async def fake_execute(tool, handler, target, flags, options):
        await gate.wait()
        return _envelope(summary="nuclei bg done", artifact="nuclei_7_7")

    monkeypatch.setattr(scan_tools, "_scan_execute", fake_execute)

    with patch.object(scan_tools, "scan_session") as msess, \
         patch.object(scan_tools, "cost_tracker") as mcost:
        msess.get.return_value = {"status": "running"}
        msess.check_limits.return_value = None
        mcost.get_summary.return_value = {}
        resp = json.loads(await scan_tools.scan("nuclei", "http://t", background=True))

    assert resp["status"] == "running"
    assert resp["tool"] == "scan:nuclei"
    job_id = resp["job_id"]
    tasks = list(jobs._JOB_TASKS)

    assert json.loads(jobs.poll_response({"job_id": job_id}))["status"] == "running"
    gate.set()
    await asyncio.gather(*tasks)
    done = json.loads(jobs.poll_response({"job_id": job_id}))
    assert done["status"] == "done"
    assert done["artifact_id"] == "nuclei_7_7"


# ---------------------------------------------------------------------------
# session() action routing
# ---------------------------------------------------------------------------

def test_session_dispatch_routes_job_actions():
    # Unknown-id poll through the session sync dispatcher.
    out = session_tools._dispatch_sync_action("job_poll", {"job_id": "nope"})
    assert json.loads(out)["status"] == "unknown"

    # job_list through the session sync dispatcher.
    listing = json.loads(session_tools._dispatch_sync_action("job_list", {}))
    assert "jobs" in listing and "max_concurrent" in listing
