import importlib

import core.paths


def test_smith_workdir_rehomes_runtime_state_only(monkeypatch, tmp_path):
    monkeypatch.setenv("SMITH_WORKDIR", str(tmp_path))

    paths = importlib.reload(core.paths)

    assert paths.SESSION_FILE == tmp_path / "session.json"
    assert paths.FINDINGS_FILE == tmp_path / "findings.json"
    assert paths.ARTIFACTS_DIR == tmp_path / "artifacts"
    assert paths.POCS_DIR == tmp_path / "pocs"
    assert paths.LOGS_DIR == tmp_path / "logs"
    assert paths.TEMPLATES_DIR == paths.REPO_ROOT / "templates"
    assert paths.DASHBOARD_DIR == paths.REPO_ROOT / "dashboard"
    assert paths.THREAT_MODEL_DIR == paths.REPO_ROOT / "threat-model"


def test_default_paths_unchanged_without_env(monkeypatch):
    monkeypatch.delenv("SMITH_WORKDIR", raising=False)

    paths = importlib.reload(core.paths)

    assert paths.SESSION_FILE == paths.REPO_ROOT / "session.json"
    assert paths.FINDINGS_FILE == paths.REPO_ROOT / "findings.json"
    assert paths.ARTIFACTS_DIR == paths.REPO_ROOT / "artifacts"
    assert paths.POCS_DIR == paths.REPO_ROOT / "pocs"
    assert paths.LOGS_DIR == paths.REPO_ROOT / "logs"
