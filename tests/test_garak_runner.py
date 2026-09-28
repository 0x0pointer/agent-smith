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
    assert "run" in argv and "--rm" in argv
    assert "--add-host=host.docker.internal:host-gateway" in argv   # reach host target x-platform
    assert "--network=host" not in argv                             # host net doesn't work on Docker Desktop
    assert "--cap-drop=ALL" in argv and "--security-opt=no-new-privileges" in argv
    assert any(a.startswith("--memory=") for a in argv)
    assert gr.GARAK_IMAGE in argv
    # config-in / report-out over the /work mount
    assert any(a == "-v" for a in argv) and any(a.endswith(":/work") for a in argv)
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
