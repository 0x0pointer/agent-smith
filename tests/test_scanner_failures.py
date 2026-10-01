"""
Issue #178 — scanners must FAIL LOUD, never return empty-as-clean.

"The worst failure mode a security scanner can have: a broken scan is reported
as a clean scan." These tests lock in the layers of the fix:

  1. build_args host-path -> /target remap for EVERY mount tool (semgrep,
     trufflehog, mobsfscan) — a host path passed verbatim does not exist in the
     container, so the tool scans nothing and exits "clean".
  2. _format_run_result — a non-ok container exit becomes a SCAN_FAILED
     sentinel, UNLESS the tool still produced usable output (a linter that
     exits non-zero *because* it found issues ran fine and keeps its findings).
  3. wrap() / _check_scan_failed — the sentinel is elevated into a VISIBLE
     failure envelope (anomaly + warning + "SCAN FAILED" summary) BEFORE any
     tool summarizer, so it cannot be swallowed into a clean "0 results".
  4. _resolve_mount — an explicit `target` is honored (overrides a stale
     PENTEST_TARGET_PATH) and a missing codebase is an explicit error, never a
     silent scan of the agent's own cwd.

Plus a docker-gated smoke test that drives the PRODUCTION path (host-path mount
+ remap) and proves trufflehog actually detects a planted secret. The secret is
generated at runtime so this repo's own scanners never flag a committed one.
"""
import json
import os
import shutil

import pytest

from tools import REGISTRY
from tools.base import SCAN_FAILED_SENTINEL
from mcp_server._app import _format_run_result, _resolve_mount


# ---------------------------------------------------------------------------
# 1. build_args remaps host paths to the /target mount (every mount tool)
# ---------------------------------------------------------------------------

class TestMountPathRemap:

    @pytest.mark.parametrize("name", ["semgrep", "trufflehog", "mobsfscan"])
    def test_host_path_is_remapped_to_target(self, name):
        # Production passes the HOST path; only /target exists in the container.
        args = REGISTRY[name].build_args(path="/Users/someone/myrepo")
        assert "/Users/someone/myrepo" not in args, f"{name} leaks the host path"
        assert any(a == "/target" or a.startswith("/target") for a in args), name

    @pytest.mark.parametrize("name", ["semgrep", "trufflehog", "mobsfscan"])
    def test_target_path_is_preserved(self, name):
        args = REGISTRY[name].build_args(path="/target")
        assert "/target" in args


# ---------------------------------------------------------------------------
# 2. _format_run_result — exit-code gating, parse-first
# ---------------------------------------------------------------------------

class TestFormatRunResultExitCode:

    def _semgrep_stdout(self):
        return json.dumps({"results": [{
            "check_id": "python.lang.security.audit",
            "path": "app.py", "start": {"line": 3},
            "extra": {"severity": "ERROR", "message": "eval", "lines": "eval(x)"},
        }]})

    def test_nonok_exit_no_output_is_failure(self):
        out = _format_run_result(REGISTRY["semgrep"], "", "fatal: bad config", exit_code=2)
        assert out.startswith(SCAN_FAILED_SENTINEL)
        assert "exited 2" in out and "BROKEN scan" in out

    def test_137_exit_includes_oom_hint(self):
        out = _format_run_result(REGISTRY["trufflehog"], "", "", exit_code=137)
        assert out.startswith(SCAN_FAILED_SENTINEL)
        assert "137" in out and "OOM" in out

    def test_stderr_is_preserved_in_failure(self):
        out = _format_run_result(REGISTRY["nmap"], "", "name resolution failed", exit_code=1)
        assert out.startswith(SCAN_FAILED_SENTINEL)
        assert "name resolution failed" in out

    def test_nonok_exit_WITH_findings_is_not_failure(self):
        # A linter that exits non-zero *because* it found issues RAN fine — its
        # findings must survive, not be discarded as a "broken scan".
        out = _format_run_result(REGISTRY["semgrep"], self._semgrep_stdout(), "", exit_code=1)
        assert not out.startswith(SCAN_FAILED_SENTINEL)
        assert len(json.loads(out)["findings"]) == 1

    def test_nonok_exit_with_raw_output_nonparser_tool_is_not_failure(self):
        out = _format_run_result(REGISTRY["nmap"], "Host is up (0.01s latency)", "", exit_code=1)
        assert not out.startswith(SCAN_FAILED_SENTINEL)
        assert "Host is up" in out

    def test_clean_exit_with_findings_still_parses(self):
        out = _format_run_result(REGISTRY["semgrep"], self._semgrep_stdout(), "", exit_code=0)
        assert not out.startswith(SCAN_FAILED_SENTINEL)
        assert len(json.loads(out)["findings"]) == 1

    def test_clean_exit_empty_is_not_a_failure(self):
        out = _format_run_result(REGISTRY["trufflehog"], "", "", exit_code=0)
        assert not out.startswith(SCAN_FAILED_SENTINEL)
        assert json.loads(out)["findings"] == []

    def test_default_ok_exit_codes_is_zero_only(self):
        for name in ("semgrep", "trufflehog", "nmap", "naabu", "httpx",
                     "nuclei", "subfinder", "mobsfscan"):
            assert REGISTRY[name].ok_exit_codes == (0,), name


# ---------------------------------------------------------------------------
# 3. wrap() — structural surfacing, routed through the REAL pipeline
# ---------------------------------------------------------------------------

@pytest.fixture
def wrap_env(tmp_path, monkeypatch):
    """A running session + a redirected artifact dir so wrap() runs end-to-end
    without writing proof files into the repo."""
    import core.session as scan_session
    import mcp_server.scan_engine.artifacts as artifacts_mod
    monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
    art = tmp_path / "artifacts"; art.mkdir()
    monkeypatch.setattr(artifacts_mod, "_ARTIFACTS_DIR", art)
    scan_session.start("https://example.com")
    return tmp_path


class TestFailureSurfacing:

    def test_non_sentinel_passes_through(self):
        from mcp_server.scan_engine.envelope import _check_scan_failed
        assert _check_scan_failed("nmap", '{"findings": []}') is None

    # Both a CODE tool (generic summarizer) and NETWORK tools (whose summarizers
    # drop non-JSON / "["-prefixed lines and would otherwise swallow the error).
    # Routing through wrap() is the real guard: if the sentinel check were ever
    # reordered AFTER summarize(), these would fail instead of silently passing.
    @pytest.mark.parametrize("tool", ["semgrep", "trufflehog", "nmap", "subfinder", "nuclei"])
    def test_failure_is_visible_not_clean(self, tool, wrap_env):
        from mcp_server.scan_engine.envelope import wrap
        raw = f"{SCAN_FAILED_SENTINEL}{tool} exited 137. BROKEN scan — do not trust."
        env = json.loads(wrap(tool, raw, {"host": "x", "domain": "x", "path": "/target"}))
        assert "SCAN FAILED" in env["summary"]
        assert env["anomalies"], "a failed scan must raise an anomaly"
        assert any("FAILED" in w for w in env["warnings"])
        for clean in ("0 open ports", "0 subdomains", "0 issues", "No findings", "0 host"):
            assert clean not in env["summary"]

    def test_failure_artifact_has_no_nul_bytes(self, wrap_env):
        import mcp_server.scan_engine.artifacts as artifacts_mod
        from mcp_server.scan_engine.envelope import wrap
        raw = f"{SCAN_FAILED_SENTINEL}semgrep exited 2. BROKEN scan."
        env = json.loads(wrap("semgrep", raw, {"path": "/target"}))
        art_id = env.get("artifact")
        if art_id:
            body = (artifacts_mod._ARTIFACTS_DIR / f"{art_id}.txt").read_text()
            assert "\x00" not in body


# ---------------------------------------------------------------------------
# 4. _resolve_mount — honor target, never silently scan cwd
# ---------------------------------------------------------------------------

class TestResolveMount:

    def test_target_overrides_stale_env(self, tmp_path, monkeypatch):
        repo_a, repo_b = tmp_path / "repoA", tmp_path / "repoB"
        repo_a.mkdir(); repo_b.mkdir()
        monkeypatch.setenv("PENTEST_TARGET_PATH", str(repo_a))
        mount, err = _resolve_mount("trufflehog", REGISTRY["trufflehog"], {"path": str(repo_b)})
        assert err is None
        assert mount == str(repo_b)

    def test_env_used_when_no_target(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"; repo.mkdir()
        monkeypatch.setenv("PENTEST_TARGET_PATH", str(repo))
        mount, err = _resolve_mount("semgrep", REGISTRY["semgrep"], {})
        assert err is None
        assert mount == str(repo)

    def test_missing_codebase_errors_and_never_scans_cwd(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PENTEST_TARGET_PATH", raising=False)
        mount, err = _resolve_mount(
            "semgrep", REGISTRY["semgrep"], {"path": str(tmp_path / "nope")})
        assert mount is None
        assert err is not None and err.startswith(SCAN_FAILED_SENTINEL)
        assert "no valid codebase" in err
        assert os.getcwd() not in err

    def test_non_mount_tool_resolves_to_none(self):
        mount, err = _resolve_mount("nmap", REGISTRY["nmap"], {"host": "example.com"})
        assert mount is None and err is None


# ---------------------------------------------------------------------------
# 5. Docker-gated smoke test — the PRODUCTION path actually detects a secret
# ---------------------------------------------------------------------------

def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    import subprocess
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


_HAS_DOCKER = _docker_up()


@pytest.mark.skipif(not _HAS_DOCKER, reason="docker daemon not available — integration smoke test")
@pytest.mark.asyncio
async def test_trufflehog_detects_planted_secret_via_production_path(tmp_path):
    """Plant a runtime-generated private key and confirm trufflehog finds it
    while driving the SAME code path production uses: mount the host dir, and
    let build_args remap the host path to /target (the bug that made every real
    trufflehog scan silently empty)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from tools.docker_runner import run_container
    from tools.trufflehog import _parse as th_parse

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (tmp_path / "leaked_id_ecdsa").write_bytes(pem)

    tool = REGISTRY["trufflehog"]
    # Pass the HOST path, exactly as _handle_trufflehog does — build_args must
    # remap it to /target, which is where tmp_path is mounted.
    args = tool.build_args(path=str(tmp_path))
    assert str(tmp_path) not in args, "host path must be remapped, not passed verbatim"
    stdout, stderr, exit_code = await run_container(
        tool.image, args, timeout=tool.default_timeout,
        mount_path=str(tmp_path), network=tool.network,
    )
    assert exit_code == 0, f"trufflehog errored: exit {exit_code}: {stderr[:300]}"
    findings = th_parse(stdout, stderr)
    assert findings, "trufflehog returned EMPTY on a tree with a planted private key"
    assert any("PrivateKey" in f.get("detector", "") for f in findings)
