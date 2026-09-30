"""Unit tests for the standalone garak runner (no Docker actually invoked)."""
import asyncio

import pytest

import tools.garak_runner as gr


class _FakeProc:
    def __init__(self, out: bytes):
        self._out = out
        self.returncode = 0

    async def communicate(self):
        return (self._out, b"")


@pytest.mark.asyncio
async def test_run_garak_builds_hardened_docker_run(monkeypatch, tmp_path):
    async def _img_present():
        return True
    monkeypatch.setattr(gr, "image_exists", _img_present)
    monkeypatch.setattr(gr, "_cache_dir", lambda: str(tmp_path / "cache"))

    cap = {}

    async def _fake_exec(*argv, stdout=None, stderr=None):
        cap["argv"] = list(argv)
        return _FakeProc(b"progress\n=== GARAK REPORT JSONL ===\n{}\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    out = await gr.run_garak(
        {"rest": {"RestGenerator": {"uri": "http://t/chat"}}},
        "dan,encoding", flags="--verbose", timeout=60,
    )

    argv = cap["argv"]
    assert "run" in argv
    assert "--rm" in argv
    assert "--add-host=host.docker.internal:host-gateway" in argv   # reach host target x-platform
    assert "--network=host" not in argv                             # host net doesn't work on Docker Desktop
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert any(a.startswith("--memory=") for a in argv)
    assert gr.GARAK_IMAGE in argv
    # config-in / report-out over the /work mount
    assert any(a == "-v" for a in argv)
    assert any(a.endswith(":/work") for a in argv)
    assert any(a.endswith(":/root/.cache") for a in argv)   # persistent model cache
    sh_cmd = argv[-1]
    assert "garak --target_type rest -G /work/garak_rest.json" in sh_cmd
    assert "--probes dan,encoding" in sh_cmd
    assert "--verbose" in sh_cmd
    assert "=== GARAK REPORT JSONL ===" in sh_cmd  # report tail appended
    assert "=== GARAK REPORT JSONL ===" in out


@pytest.mark.asyncio
async def test_run_garak_degrades_when_image_missing_and_autobuild_off(monkeypatch):
    async def _no_img():
        return False
    monkeypatch.setattr(gr, "image_exists", _no_img)
    monkeypatch.setenv("SMITH_GARAK_AUTOBUILD", "0")
    out = await gr.run_garak({"rest": {}}, "dan", timeout=5)
    assert "garak unavailable" in out
    assert "docker build -t" in out


@pytest.mark.asyncio
async def test_ai_env_forwards_aitest_key_as_anthropic(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("AITEST_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    flags = gr._ai_env_flags()
    assert "ANTHROPIC_API_KEY=sk-ant-test" in flags   # renamed key exposed as ANTHROPIC_API_KEY
    assert "OPENAI_API_KEY=sk-openai" in flags


@pytest.mark.asyncio
async def test_list_probes_runs_and_caches(monkeypatch):
    gr._PROBE_LIST_CACHE.clear()

    async def _img_present():
        return True
    monkeypatch.setattr(gr, "image_exists", _img_present)

    calls = []

    async def _fake_exec(*argv, stdout=None, stderr=None):
        calls.append(argv)
        return _FakeProc(b"   probes: dan.AntiDAN\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    out = await gr.list_probes()
    assert "dan.AntiDAN" in out
    out2 = await gr.list_probes()          # cached — no second docker run
    assert out2 == out
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_list_probes_empty_when_image_unavailable(monkeypatch):
    gr._PROBE_LIST_CACHE.clear()

    async def _no_img():
        return False
    monkeypatch.setattr(gr, "image_exists", _no_img)
    monkeypatch.setenv("SMITH_GARAK_AUTOBUILD", "0")   # ensure_image returns (False, …), no build

    assert await gr.list_probes() == ""


@pytest.mark.asyncio
async def test_list_probes_failsoft_on_exec_error(monkeypatch):
    gr._PROBE_LIST_CACHE.clear()

    async def _img_present():
        return True
    monkeypatch.setattr(gr, "image_exists", _img_present)

    async def _boom(*a, **k):
        raise RuntimeError("docker gone")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _boom)

    assert await gr.list_probes() == ""


# ── streaming + reaping + partial-on-timeout + parallelism ────────────────────

_EVAL_LINE = ('{"entry_type": "eval", "probe": "dan.AntiDAN", "detector": "mitigation.MitigationBypass",'
              ' "passed": 3, "total": 5}')


def test_build_garak_cmd_parallel(monkeypatch):
    monkeypatch.setattr(gr, "_PARALLEL", 8)
    cmd = gr._build_garak_cmd("dan,encoding", "")
    assert "--parallel_attempts 8" in cmd
    assert "--probes dan,encoding" in cmd
    assert "=== GARAK REPORT JSONL ===" in cmd
    monkeypatch.setattr(gr, "_PARALLEL", 1)                 # 1 disables parallelism
    assert "--parallel_attempts" not in gr._build_garak_cmd("dan", "")


def test_report_block_reads_evals(tmp_path):
    wd = tmp_path / "wd"
    wd.mkdir()
    (wd / "run.report.jsonl").write_text(
        '{"entry_type": "attempt", "seq": 1}\n' + _EVAL_LINE + "\n", encoding="utf-8")
    block = gr._report_block(str(wd), note="[partial]")
    assert block.startswith("[partial]")
    assert "=== GARAK REPORT JSONL ===" in block
    assert '"entry_type": "eval"' in block            # the eval line survives
    # missing file → still a well-formed (empty) block, never raises
    assert "=== GARAK REPORT JSONL ===" in gr._report_block(str(tmp_path / "nope"))


class _HangingProc:
    """communicate() blocks until kill() is called (to drive the timeout path)."""
    def __init__(self):
        self._killed = False
        self.returncode = None

    def kill(self):
        self._killed = True
        self.returncode = -9

    async def communicate(self):
        while not self._killed:
            await asyncio.sleep(0.02)
        return (b"", b"")


@pytest.mark.asyncio
async def test_run_garak_timeout_reaps_and_returns_partial(monkeypatch, tmp_path):
    async def _img_present():
        return True
    monkeypatch.setattr(gr, "image_exists", _img_present)
    monkeypatch.setattr(gr, "_cache_dir", lambda: str(tmp_path / "cache"))

    wd = tmp_path / "wd"
    wd.mkdir()
    (wd / "run.report.jsonl").write_text(_EVAL_LINE + "\n", encoding="utf-8")
    monkeypatch.setattr(gr.tempfile, "mkdtemp", lambda **k: str(wd))

    run_argv = {}
    kills = []
    hanging = _HangingProc()

    async def _fake_exec(*argv, stdout=None, stderr=None):
        if "kill" in argv:
            kills.append(argv)
            return _FakeProc(b"")
        run_argv["argv"] = list(argv)
        return hanging
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    out = await gr.run_garak({"rest": {}}, "dan", timeout=0.2)

    # named container so it can be reaped
    assert "--name" in run_argv["argv"]
    cname = run_argv["argv"][run_argv["argv"].index("--name") + 1]
    assert cname.startswith("smith_garak_")
    # the orphan was killed by name, and the PARTIAL report came back (not an exception)
    assert kills and cname in kills[0]
    assert "timed out after 0.2s" in out
    assert '"entry_type": "eval"' in out


class _SlowProc:
    def __init__(self, out: bytes, delay: float):
        self._out, self._delay, self.returncode = out, delay, 0

    def kill(self):
        pass

    async def communicate(self):
        await asyncio.sleep(self._delay)
        return (self._out, b"")


@pytest.mark.asyncio
async def test_run_garak_streams_progress(monkeypatch, tmp_path):
    async def _img_present():
        return True
    monkeypatch.setattr(gr, "image_exists", _img_present)
    monkeypatch.setattr(gr, "_cache_dir", lambda: str(tmp_path / "cache"))
    monkeypatch.setattr(gr, "_PROGRESS_SECS", 0.05)        # tick fast for the test

    wd = tmp_path / "wd"
    wd.mkdir()
    (wd / "run.report.jsonl").write_text(_EVAL_LINE + "\n", encoding="utf-8")
    monkeypatch.setattr(gr.tempfile, "mkdtemp", lambda **k: str(wd))

    async def _fake_exec(*argv, stdout=None, stderr=None):
        return _SlowProc(b"done\n=== GARAK REPORT JSONL ===\n" + _EVAL_LINE.encode() + b"\n", 0.25)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    seen = []
    await gr.run_garak({"rest": {}}, "dan", timeout=30, on_progress=lambda b: seen.append(b))

    assert seen, "progress callback was never invoked during the run"
    assert any("=== GARAK REPORT JSONL ===" in b and '"entry_type": "eval"' in b for b in seen)
