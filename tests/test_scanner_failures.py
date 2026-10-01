"""
Issue #178 — scanners must FAIL LOUD, never return empty-as-clean.

"The worst failure mode a security scanner can have: a broken scan is reported
as a clean scan." These tests lock in the three layers of the fix:

  1. _format_run_result  — a non-ok container exit (crash / OOM-137 / config
     error) becomes a SCAN_FAILED sentinel, not an empty findings envelope;
     a genuinely clean exit-0 run is still a normal (possibly empty) result.
  2. wrap() / _check_scan_failed — the sentinel is elevated into a VISIBLE
     failure envelope (anomaly + warning + "SCAN FAILED" summary) for EVERY
     tool, so it cannot be swallowed into a clean-looking "0 results" by a
     tool-specific summarizer (the net.py summarizers drop non-JSON lines).
  3. _resolve_mount — an explicit `target` is honored (overrides a stale
     PENTEST_TARGET_PATH) and a missing codebase is an explicit error, never
     a silent scan of the agent's own cwd.

Plus a docker-gated smoke test that proves the scanners actually DETECT a
planted secret in a fixture (the reporter's "scan the fixture" ask). The
secret is generated at runtime so this repo's own secret scanners never flag
a committed credential.
"""
import json
import os
import shutil

import pytest

from tools import REGISTRY
from tools.base import SCAN_FAILED_SENTINEL
from mcp_server._app import _format_run_result, _resolve_mount


# ---------------------------------------------------------------------------
# 1. _format_run_result — exit-code gating
# ---------------------------------------------------------------------------

class TestFormatRunResultExitCode:

    def test_nonok_exit_yields_sentinel(self):
        out = _format_run_result(REGISTRY["semgrep"], "", "fatal: bad config", exit_code=2)
        assert out.startswith(SCAN_FAILED_SENTINEL)
        assert "exited 2" in out
        assert "BROKEN scan" in out

    def test_137_exit_includes_oom_hint(self):
        out = _format_run_result(REGISTRY["trufflehog"], "partial", "", exit_code=137)
        assert out.startswith(SCAN_FAILED_SENTINEL)
        assert "137" in out and "OOM" in out

    def test_stderr_is_preserved_in_failure(self):
        out = _format_run_result(REGISTRY["nmap"], "", "name resolution failed", exit_code=1)
        assert out.startswith(SCAN_FAILED_SENTINEL)
        assert "name resolution failed" in out

    def test_clean_exit_with_findings_still_parses(self):
        # semgrep exits 0 even WITH findings — a real-findings run must NOT be
        # misclassified as a failure.
        stdout = json.dumps({"results": [{
            "check_id": "python.lang.security.audit",
            "path": "app.py",
            "start": {"line": 3},
            "extra": {"severity": "ERROR", "message": "eval", "lines": "eval(x)"},
        }]})
        out = _format_run_result(REGISTRY["semgrep"], stdout, "", exit_code=0)
        assert not out.startswith(SCAN_FAILED_SENTINEL)
        assert len(json.loads(out)["findings"]) == 1

    def test_clean_exit_empty_is_not_a_failure(self):
        # Genuinely clean: exit 0, no output -> normal empty envelope, not sentinel.
        out = _format_run_result(REGISTRY["trufflehog"], "", "", exit_code=0)
        assert not out.startswith(SCAN_FAILED_SENTINEL)
        assert json.loads(out)["findings"] == []

    def test_default_ok_exit_codes_is_zero_only(self):
        # Guards the audited policy: every current tool treats only 0 as success.
        for name in ("semgrep", "trufflehog", "nmap", "naabu", "httpx",
                     "nuclei", "subfinder", "mobsfscan"):
            assert REGISTRY[name].ok_exit_codes == (0,), name


# ---------------------------------------------------------------------------
# 2. wrap() / _check_scan_failed — structural surfacing for EVERY tool
# ---------------------------------------------------------------------------

class TestFailureSurfacing:

    def _failed_envelope(self, tool, headline):
        from mcp_server.scan_engine.envelope import _check_scan_failed
        raw = f"{SCAN_FAILED_SENTINEL}{headline}\nstderr:\nboom"
        out = _check_scan_failed(tool, raw, {})
        assert out is not None, "sentinel must be recognised as a failure"
        return json.loads(out)

    def test_non_sentinel_passes_through(self):
        from mcp_server.scan_engine.envelope import _check_scan_failed
        assert _check_scan_failed("nmap", '{"findings": []}', {}) is None

    @pytest.mark.parametrize("tool", ["semgrep", "trufflehog", "nmap", "subfinder", "nuclei"])
    def test_failure_is_visible_not_clean(self, tool):
        # The core regression guard: a broken scan must read as a failure in the
        # summary + anomalies + warnings for BOTH code tools (generic summarizer)
        # and network tools (whose summarizers would otherwise swallow it).
        env = self._failed_envelope(tool, f"{tool} exited 137")
        assert "SCAN FAILED" in env["summary"]
        assert env["anomalies"], "a failed scan must raise an anomaly"
        assert any("FAILED" in w for w in env["warnings"])
        # Must NOT be rendered as a reassuring empty result.
        for clean in ("0 open ports", "0 subdomains", "0 issues", "No findings"):
            assert clean not in env["summary"]

    def test_wrap_short_circuits_before_summarizer(self, tmp_path, monkeypatch):
        import core.session as scan_session
        monkeypatch.setattr(scan_session, "_SESSION_FILE", tmp_path / "session.json")
        scan_session.start("https://example.com")
        from mcp_server.scan_engine.envelope import wrap
        raw = f"{SCAN_FAILED_SENTINEL}subfinder exited 137. BROKEN scan."
        env = json.loads(wrap("subfinder", raw, {"domain": "example.com"}))
        assert "SCAN FAILED" in env["summary"]
        assert env["anomalies"]


# ---------------------------------------------------------------------------
# 3. _resolve_mount — honor target, never silently scan cwd
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
        # The old bug: silently mounting cwd. The error must not name cwd as a target.
        assert os.getcwd() not in err

    def test_non_mount_tool_resolves_to_none(self):
        mount, err = _resolve_mount("nmap", REGISTRY["nmap"], {"host": "example.com"})
        assert mount is None and err is None


# ---------------------------------------------------------------------------
# 4. Docker-gated smoke test — scanners actually detect a planted secret
# ---------------------------------------------------------------------------

_HAS_DOCKER = shutil.which("docker") is not None


@pytest.mark.skipif(not _HAS_DOCKER, reason="docker not available — integration smoke test")
@pytest.mark.asyncio
async def test_trufflehog_detects_planted_secret(tmp_path):
    """Plant a real (throwaway, runtime-generated) private key and confirm
    trufflehog finds it — the guard that an EMPTY result means clean, not broken."""
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
    stdout, stderr, exit_code = await run_container(
        tool.image, tool.build_args(path="/target"),
        timeout=tool.default_timeout, mount_path=str(tmp_path),
        network=tool.network,
    )
    assert exit_code == 0, f"trufflehog errored: exit {exit_code}: {stderr[:300]}"
    findings = th_parse(stdout, stderr)
    assert findings, "trufflehog returned EMPTY on a tree with a planted private key"
    assert any("PrivateKey" in f.get("detector", "") for f in findings)
