"""A scan reaching a terminal state stops the pentest command-execution containers
(Kali/MSF/MobSF) — so a finished scan leaves no running RCE endpoint. Covers the human
complete + force-complete paths, the auto limit_reached path, the SMITH_KEEP_CONTAINERS
opt-out, the once-only guard, and fail-soft."""
import subprocess

import core.session as cs
import tools.docker_cli as dc
from core.session import lifecycle as lc
from core.session import limits as lim


def _running(monkeypatch):
    """Install a running session with the flush/reconcile side-effects stubbed."""
    monkeypatch.setattr(cs, "_current", {"id": "s", "status": "running",
                                         "limits": {"max_cost_usd": 1, "max_time_minutes": 1, "max_tool_calls": 1}})
    monkeypatch.setattr(cs, "_flush", lambda: None)
    monkeypatch.setattr(cs, "_reconcile_if_external_write", lambda: None)


def _capture_docker(monkeypatch):
    """Record docker invocations instead of running them; unset the test opt-out so the
    teardown actually fires."""
    monkeypatch.delenv("SMITH_KEEP_CONTAINERS", raising=False)
    monkeypatch.setattr(dc, "docker_executable", lambda: "docker")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda argv, *a, **k: calls.append(argv))
    return calls


def test_complete_stops_all_three_containers(monkeypatch):
    _running(monkeypatch)
    calls = _capture_docker(monkeypatch)
    lc.complete(notes="done")
    assert cs._current["status"] == "complete"
    assert calls, "docker stop was not invoked"
    argv = calls[0]
    assert argv[:2] == ["docker", "stop"]
    assert {"pentest-kali", "pentest-metasploit", "pentest-mobsf"} <= set(argv)


def test_force_complete_also_stops(monkeypatch):
    _running(monkeypatch)
    calls = _capture_docker(monkeypatch)
    lc.complete(notes="forced", quality_gate="failed")
    assert cs._current["status"] == "incomplete_with_unresolved_blockers"
    assert calls and "pentest-kali" in calls[0]


def test_limit_reached_stops(monkeypatch):
    _running(monkeypatch)
    calls = _capture_docker(monkeypatch)
    lim._stop("limit_reached", "COST LIMIT hit")
    assert cs._current["status"] == "limit_reached"
    assert calls and "pentest-metasploit" in calls[0]


def test_keep_containers_opt_out(monkeypatch):
    _running(monkeypatch)
    monkeypatch.setattr(dc, "docker_executable", lambda: "docker")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda argv, *a, **k: calls.append(argv))
    monkeypatch.setenv("SMITH_KEEP_CONTAINERS", "1")
    lc.complete(notes="done")
    assert cs._current["status"] == "complete"       # still completes
    assert not calls                                  # ...but containers are left running


def test_not_re_triggered_on_already_terminal(monkeypatch):
    # complete() only acts on running→terminal, so a second call must NOT stop again
    monkeypatch.setattr(cs, "_current", {"id": "s", "status": "complete"})
    monkeypatch.setattr(cs, "_flush", lambda: None)
    monkeypatch.setattr(cs, "_reconcile_if_external_write", lambda: None)
    calls = _capture_docker(monkeypatch)
    lc.complete(notes="again")
    assert not calls                                  # no-op on an already-terminal scan


def test_fail_soft_when_docker_errors(monkeypatch):
    _running(monkeypatch)
    monkeypatch.delenv("SMITH_KEEP_CONTAINERS", raising=False)
    monkeypatch.setattr(dc, "docker_executable", lambda: "docker")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("docker missing")))
    lc.complete(notes="done")                          # must NOT raise
    assert cs._current["status"] == "complete"         # completion still succeeded