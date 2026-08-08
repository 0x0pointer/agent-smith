from tools import docker_cli


def _make_executable(path):
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_docker_executable_prefers_valid_env_override(tmp_path, monkeypatch):
    docker_bin = _make_executable(tmp_path / "docker-env")

    monkeypatch.setenv("DOCKER_BIN", str(docker_bin))
    monkeypatch.setattr(docker_cli.shutil, "which", lambda _: "/usr/bin/docker")

    assert docker_cli.docker_executable() == str(docker_bin)


def test_docker_executable_ignores_invalid_env_override(tmp_path, monkeypatch):
    invalid_docker_bin = tmp_path / "missing-docker"

    monkeypatch.setenv("DOCKER_BIN", str(invalid_docker_bin))
    monkeypatch.setattr(docker_cli.shutil, "which", lambda _: "/path/docker")

    assert docker_cli.docker_executable() == "/path/docker"


def test_docker_executable_uses_path_lookup(monkeypatch):
    monkeypatch.delenv("DOCKER_BIN", raising=False)
    monkeypatch.setattr(docker_cli.shutil, "which", lambda _: "/opt/bin/docker")

    assert docker_cli.docker_executable() == "/opt/bin/docker"


def test_docker_executable_uses_known_candidate_when_path_misses(tmp_path, monkeypatch):
    candidate = _make_executable(tmp_path / "docker")

    monkeypatch.delenv("DOCKER_BIN", raising=False)
    monkeypatch.setattr(docker_cli.shutil, "which", lambda _: None)
    monkeypatch.setattr(docker_cli, "_DOCKER_CANDIDATES", (str(candidate),))

    assert docker_cli.docker_executable() == str(candidate)


def test_docker_executable_falls_back_to_command_name(monkeypatch):
    monkeypatch.delenv("DOCKER_BIN", raising=False)
    monkeypatch.setattr(docker_cli.shutil, "which", lambda _: None)
    monkeypatch.setattr(docker_cli, "_DOCKER_CANDIDATES", ())

    assert docker_cli.docker_executable() == "docker"


def test_is_executable_rejects_missing_file(tmp_path):
    assert docker_cli._is_executable(str(tmp_path / "docker")) is False


def test_is_executable_rejects_non_executable_file(tmp_path):
    docker_bin = tmp_path / "docker"
    docker_bin.write_text("#!/bin/sh\n")

    assert docker_cli._is_executable(str(docker_bin)) is False


def test_is_executable_accepts_executable_file(tmp_path):
    docker_bin = _make_executable(tmp_path / "docker")

    assert docker_cli._is_executable(str(docker_bin)) is True
