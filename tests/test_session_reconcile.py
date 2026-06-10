"""
Tests for cross-process state reconciliation in core.session.

The dashboard process and the MCP server process each keep their own
in-memory ``_current`` and write back to ``session.json``. Without
reconciliation, a write in process A is silently undone by a stale
``_flush()`` in process B — e.g. the operator clicks Complete Scan on the
dashboard, then the MCP's next tool call flushes its still-"running" copy
on top of the dashboard's write.

These tests simulate the race directly:

1. Start a session in "process A" (the test's interpreter).
2. Write a different state to session.json out-of-band (simulating
   "process B" — the dashboard — committing while we weren't looking).
3. Call a mutation in process A and verify it reconciled to the
   external state instead of overwriting it.
"""
import json
import os
import time
from pathlib import Path

import pytest

from core import session as scan_session


@pytest.fixture
def isolated_session(tmp_path, monkeypatch):
    """Sandbox session.json + logs dir; reset module state before/after."""
    monkeypatch.setattr(scan_session, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    scan_session._current = None
    scan_session._last_local_write_mtime = 0.0
    yield tmp_path
    scan_session._current = None
    scan_session._last_local_write_mtime = 0.0


def _write_external_state(session_file: Path, **overrides) -> None:
    """Simulate another process writing to session.json. Also bumps the
    on-disk mtime so the local reconcile-check actually triggers."""
    data = json.loads(session_file.read_text())
    data.update(overrides)
    session_file.write_text(json.dumps(data, indent=2))
    # Force a measurable mtime gap. Some filesystems have 1s granularity,
    # but most modern macOS/Linux mounts are sub-µs. We bump explicitly to
    # be deterministic across CI environments.
    later = time.time() + 5.0
    os.utime(session_file, (later, later))


# ---------------------------------------------------------------------------
# The motivating bug: dashboard completes, MCP's next mutation must NOT undo it
# ---------------------------------------------------------------------------

class TestCompleteSurvivesMCPTrailingFlush:

    def test_dashboard_complete_survives_subsequent_add_tool_called(self, isolated_session):
        """The bug: operator clicks Complete, status flips to 'complete' on
        disk. MCP server (which still has status='running' in memory) makes
        a tool call that triggers ``add_tool_called`` → ``_flush()``. Without
        reconcile, the in-memory 'running' overwrites the on-disk 'complete'.
        With reconcile, ``add_tool_called`` notices disk changed, reloads,
        sees status='complete', and refuses to mutate."""
        scan_session.start(target="http://x.test", depth="quick")
        # Simulate dashboard completing the scan out-of-band:
        _write_external_state(
            isolated_session / "session.json",
            status="complete",
            finished="2026-06-10T08:00:00+00:00",
        )
        # Now the "MCP process" (us) calls add_tool_called with its stale
        # in-memory state still saying "running".
        scan_session.add_tool_called("mcp_tool_called_after_complete")

        # Verify on-disk status is still "complete" — the reconcile blocked
        # the stale flush.
        on_disk = json.loads((isolated_session / "session.json").read_text())
        assert on_disk["status"] == "complete"
        assert on_disk["finished"] == "2026-06-10T08:00:00+00:00"
        # The stale tool should NOT have been appended either.
        assert "mcp_tool_called_after_complete" not in on_disk.get("tools_called", [])

    def test_dashboard_complete_survives_subsequent_set_skill(self, isolated_session):
        """set_skill is the other hot path Smith hits between tool calls."""
        scan_session.start(target="http://x.test", depth="quick")
        _write_external_state(isolated_session / "session.json", status="complete")
        scan_session.set_skill("post-exploit", reason="should be blocked")

        on_disk = json.loads((isolated_session / "session.json").read_text())
        assert on_disk["status"] == "complete"
        assert on_disk.get("skill") != "post-exploit"

    def test_dashboard_complete_survives_subsequent_trigger_gate(self, isolated_session):
        scan_session.start(target="http://x.test", depth="quick")
        _write_external_state(isolated_session / "session.json", status="complete")
        scan_session.trigger_gate("g1", "trigger", ["skill_x"])

        on_disk = json.loads((isolated_session / "session.json").read_text())
        assert on_disk["status"] == "complete"
        assert not any(g.get("id") == "g1" for g in on_disk.get("gates", []))

    def test_dashboard_complete_survives_subsequent_record_spider_failure(self, isolated_session):
        scan_session.start(target="http://x.test", depth="quick")
        _write_external_state(isolated_session / "session.json", status="complete")
        scan_session.record_spider_failure("http://x.test/foo")

        on_disk = json.loads((isolated_session / "session.json").read_text())
        assert on_disk["status"] == "complete"
        assert not on_disk.get("spider_failures")

    def test_dashboard_complete_survives_subsequent_complete_call(self, isolated_session):
        """Smith calls session(action='complete') after the dashboard
        already completed. The status should remain 'complete' (set by the
        dashboard's path) — Smith's complete() must NOT overwrite the
        dashboard's `finished` timestamp."""
        scan_session.start(target="http://x.test", depth="quick")
        _write_external_state(
            isolated_session / "session.json",
            status="complete",
            finished="2026-06-10T08:00:00+00:00",
            notes="completed by operator",
        )
        scan_session.complete(notes="completed by smith — later")

        on_disk = json.loads((isolated_session / "session.json").read_text())
        # The dashboard's finished timestamp + notes are preserved
        # (Smith's later complete() should be a no-op once status != "running").
        assert on_disk["finished"] == "2026-06-10T08:00:00+00:00"
        assert on_disk["notes"] == "completed by operator"


# ---------------------------------------------------------------------------
# The MCP-completes-while-dashboard-triggers-intervention race
# ---------------------------------------------------------------------------

class TestInterventionSurvivesMutationRace:

    def test_external_intervention_survives_local_mutation(self, isolated_session):
        """The MCP server fires an HIR (writes status='intervention_required'
        to disk). The dashboard process — still believing the session is
        running — must NOT overwrite that intervention via a subsequent
        ``set_step`` call.

        This is the inverse of the Complete-button bug, same mechanism."""
        scan_session.start(target="http://x.test", depth="quick")
        _write_external_state(
            isolated_session / "session.json",
            status="intervention_required",
            intervention={"code": "HIR_AUTH_FAILURE", "situation": "401"},
        )
        # Dashboard process's stale in-memory state still has status=running
        scan_session.set_step("5_nuclei_scan")

        on_disk = json.loads((isolated_session / "session.json").read_text())
        assert on_disk["status"] == "intervention_required"
        assert on_disk["intervention"]["code"] == "HIR_AUTH_FAILURE"


# ---------------------------------------------------------------------------
# Reconcile mechanics (verify the helper behaves correctly in isolation)
# ---------------------------------------------------------------------------

class TestReconcileMechanics:

    def test_reconcile_no_op_when_disk_matches_last_write(self, isolated_session):
        """If we just wrote and nobody changed disk, reconcile is a no-op
        and keeps the in-memory state intact."""
        scan_session.start(target="http://x.test", depth="quick")
        before = dict(scan_session._current or {})
        scan_session._reconcile_if_external_write()
        assert scan_session._current == before

    def test_reconcile_reloads_when_disk_newer(self, isolated_session):
        """Disk modified externally → in-memory state catches up."""
        scan_session.start(target="http://x.test", depth="quick")
        _write_external_state(
            isolated_session / "session.json",
            status="intervention_required",
        )
        assert scan_session._current["status"] == "running"  # stale local copy
        scan_session._reconcile_if_external_write()
        assert scan_session._current["status"] == "intervention_required"

    def test_reconcile_handles_missing_file_silently(self, isolated_session):
        """No session.json on disk yet → reconcile is a clean no-op."""
        scan_session._reconcile_if_external_write()   # must not raise

    def test_reconcile_handles_malformed_json_silently(self, isolated_session):
        """Half-written or corrupt session.json → keep our local state."""
        scan_session.start(target="http://x.test", depth="quick")
        (isolated_session / "session.json").write_text("{ not valid json")
        # Bump mtime so reconcile actually tries to read.
        later = time.time() + 5.0
        os.utime(isolated_session / "session.json", (later, later))
        scan_session._reconcile_if_external_write()
        # State is preserved; malformed-disk doesn't blow up the caller.
        assert scan_session._current is not None
        assert scan_session._current.get("target") == "http://x.test"

    def test_flush_records_mtime(self, isolated_session):
        """After ``_flush()``, ``_last_local_write_mtime`` should equal the
        new on-disk mtime so the very next reconcile is a no-op."""
        scan_session.start(target="http://x.test", depth="quick")
        # `start()` ends with `_flush()` — verify mtime was captured.
        disk_mtime = (isolated_session / "session.json").stat().st_mtime
        assert abs(scan_session._last_local_write_mtime - disk_mtime) < 0.001
