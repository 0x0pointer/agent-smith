import importlib
from pathlib import Path

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


def test_gitignore_covers_generated_run_workdirs():
    entries = Path(".gitignore").read_text(encoding="utf-8").splitlines()

    assert "runs/" in entries


def test_log_lines_are_tagged_with_the_run_id(monkeypatch):
    import logging

    from core import logger as smith_logger

    record = logging.LogRecord("pentest", logging.INFO, __file__, 1, "TOOL_CALL x", None, None)
    monkeypatch.setenv("SMITH_RUN_ID", "run-abc123")
    smith_logger._RunTagFilter().filter(record)
    assert "[run-abc123]" in smith_logger._fmt.format(record)

    # Classic single-run mode keeps the original untagged format.
    monkeypatch.delenv("SMITH_RUN_ID", raising=False)
    record = logging.LogRecord("pentest", logging.INFO, __file__, 1, "TOOL_CALL x", None, None)
    smith_logger._RunTagFilter().filter(record)
    assert "[" not in smith_logger._fmt.format(record).split("TOOL_CALL")[0].split("INFO")[1]
