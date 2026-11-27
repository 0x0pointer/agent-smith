import pytest

import core.session.lifecycle as lifecycle
from tools import kali_runner, metasploit_runner, mobsf_runner


class _FakeProc:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def wait(self):
        return self.returncode

    async def communicate(self):
        return self._stdout, self._stderr


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeClientSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, *args, **kwargs):
        return _FakeResponse(status=200)


def _patch_aiohttp(monkeypatch):
    class _FakeTimeout:
        def __init__(self, total):
            self.total = total

    monkeypatch.setattr(
        "aiohttp.ClientSession",
        lambda *args, **kwargs: _FakeClientSession(),
    )
    monkeypatch.setattr("aiohttp.ClientTimeout", _FakeTimeout)


def _patch_subprocess(monkeypatch, port_map, run_calls):
    created_networks = set()

    async def _fake_exec(*argv, **kwargs):
        argv = list(argv)
        if argv[1:3] == ["image", "inspect"]:
            return _FakeProc(returncode=0)
        if argv[1:3] == ["inspect", "--format={{.State.Running}}"]:
            return _FakeProc(returncode=0, stdout=b"false")
        if argv[1:3] == ["network", "inspect"]:
            name = argv[3]
            return _FakeProc(returncode=0 if name in created_networks else 1)
        if argv[1:3] == ["network", "create"]:
            created_networks.add(argv[3])
            return _FakeProc(returncode=0)
        if argv[1] == "run":
            run_calls.append(argv)
            return _FakeProc(returncode=0)
        if argv[1] == "port":
            key = (argv[2], argv[3])
            return _FakeProc(returncode=0, stdout=f"127.0.0.1:{port_map[key]}".encode())
        return _FakeProc(returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)


async def _noop_async():
    return None


@pytest.mark.asyncio
async def test_kali_run_uses_run_scoped_name_network_and_ephemeral_port(monkeypatch):
    monkeypatch.setenv("SMITH_RUN_ID", "Run A")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    run_calls = []
    _patch_aiohttp(monkeypatch)
    _patch_subprocess(
        monkeypatch,
        {
            ("smith-kali-run-a", "5000/tcp"): 41001,
        },
        run_calls,
    )
    monkeypatch.setattr(kali_runner, "_seed_curl_defaults", _noop_async)
    monkeypatch.setattr(kali_runner, "_register_scanner_ips", _noop_async)

    ok, msg = await kali_runner.ensure_running()

    assert ok is True
    assert msg == "started"
    assert kali_runner.container_name() == "smith-kali-run-a"
    assert kali_runner.network_name() == "smith-run-run-a"
    assert kali_runner.api_publish_arg() == "127.0.0.1::5000"
    assert kali_runner.api_url() == "http://127.0.0.1:41001"
    kali_run = next(argv for argv in run_calls if argv[2] == "-d" and "smith-kali-run-a" in argv)
    assert ["--network", "smith-run-run-a"] == kali_run[kali_run.index("--network"):kali_run.index("--network") + 2]
    assert "1080:1080" not in kali_run
    assert "8888:8888" not in kali_run
    assert "8889:8889" not in kali_run
    assert "11601:11601" not in kali_run


@pytest.mark.asyncio
async def test_two_run_apis_do_not_collide(monkeypatch):
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    run_calls = []
    _patch_aiohttp(monkeypatch)
    _patch_subprocess(
        monkeypatch,
        {
            ("smith-kali-run-a", "5000/tcp"): 41001,
            ("smith-metasploit-run-a", "5000/tcp"): 41002,
            ("smith-mobsf-run-a", "8000/tcp"): 41003,
            ("smith-kali-run-b", "5000/tcp"): 42001,
            ("smith-metasploit-run-b", "5000/tcp"): 42002,
            ("smith-mobsf-run-b", "8000/tcp"): 42003,
        },
        run_calls,
    )
    monkeypatch.setattr(kali_runner, "_seed_curl_defaults", _noop_async)
    monkeypatch.setattr(kali_runner, "_register_scanner_ips", _noop_async)

    monkeypatch.setenv("SMITH_RUN_ID", "run-a")
    assert await kali_runner.ensure_running() == (True, "started")
    assert await metasploit_runner.ensure_running() == (True, "started")
    assert await mobsf_runner.ensure_running() == (True, "started")
    urls_a = {
        kali_runner.api_url(),
        metasploit_runner.api_url(),
        mobsf_runner.api_url(),
    }

    monkeypatch.setenv("SMITH_RUN_ID", "run-b")
    assert await kali_runner.ensure_running() == (True, "started")
    assert await metasploit_runner.ensure_running() == (True, "started")
    assert await mobsf_runner.ensure_running() == (True, "started")
    urls_b = {
        kali_runner.api_url(),
        metasploit_runner.api_url(),
        mobsf_runner.api_url(),
    }

    assert urls_a.isdisjoint(urls_b)
    assert kali_runner.container_name() == "smith-kali-run-b"
    assert metasploit_runner.container_name() == "smith-metasploit-run-b"
    assert mobsf_runner.container_name() == "smith-mobsf-run-b"
    flat_runs = [" ".join(argv) for argv in run_calls if argv[1] == "run"]
    assert all(" 1080:1080" not in f" {argv}" for argv in flat_runs)
    assert all(" 8888:8888" not in f" {argv}" for argv in flat_runs)
    assert all(" 8889:8889" not in f" {argv}" for argv in flat_runs)
    assert all(" 11601:11601" not in f" {argv}" for argv in flat_runs)
    assert all(" 4444:4444" not in f" {argv}" for argv in flat_runs)
    assert all(" 4445:4445" not in f" {argv}" for argv in flat_runs)
    assert all(" 1081:1081" not in f" {argv}" for argv in flat_runs)


def test_stop_only_current_run_containers(monkeypatch):
    seen = {}

    def _fake_run(argv, **kwargs):
        seen["argv"] = argv
        class _Proc:
            returncode = 0
        return _Proc()

    monkeypatch.delenv("SMITH_KEEP_CONTAINERS", raising=False)
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    monkeypatch.setenv("SMITH_RUN_ID", "run-a")
    monkeypatch.setattr("subprocess.run", _fake_run)

    lifecycle.stop_pentest_containers()

    assert "smith-kali-run-a" in seen["argv"]
    assert "smith-metasploit-run-a" in seen["argv"]
    assert "smith-mobsf-run-a" in seen["argv"]
    assert "smith-kali-run-b" not in seen["argv"]
