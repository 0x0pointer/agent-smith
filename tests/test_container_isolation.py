import core.session.lifecycle as lifecycle
from tools import kali_runner, metasploit_runner, mobsf_runner


def test_kali_run_uses_run_scoped_name_network_and_ephemeral_port(monkeypatch):
    monkeypatch.setenv("SMITH_RUN_ID", "Run A")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    kali_runner.remember_api_port(41001)

    assert kali_runner.container_name() == "smith-kali-run-a"
    assert kali_runner.network_name() == "smith-run-run-a"
    assert kali_runner.api_publish_arg() == "127.0.0.1::5000"
    assert kali_runner.api_url() == "http://127.0.0.1:41001"


def test_two_run_apis_do_not_collide(monkeypatch):
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)

    monkeypatch.setenv("SMITH_RUN_ID", "run-a")
    kali_runner.remember_api_port(41001)
    metasploit_runner.remember_api_port(41002)
    mobsf_runner.remember_api_port(41003)
    urls_a = {
        kali_runner.api_url(),
        metasploit_runner.api_url(),
        mobsf_runner.api_url(),
    }

    monkeypatch.setenv("SMITH_RUN_ID", "run-b")
    kali_runner.remember_api_port(42001)
    metasploit_runner.remember_api_port(42002)
    mobsf_runner.remember_api_port(42003)
    urls_b = {
        kali_runner.api_url(),
        metasploit_runner.api_url(),
        mobsf_runner.api_url(),
    }

    assert urls_a.isdisjoint(urls_b)
    assert kali_runner.container_name() == "smith-kali-run-b"
    assert metasploit_runner.container_name() == "smith-metasploit-run-b"
    assert mobsf_runner.container_name() == "smith-mobsf-run-b"


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
