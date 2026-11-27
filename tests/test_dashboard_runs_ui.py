from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_sessions_tab_uses_runs_api_for_platform_run_management():
    script = (REPO_ROOT / "dashboard" / "js" / "sessions.js").read_text(encoding="utf-8")
    markup = (REPO_ROOT / "dashboard" / "tabs" / "sessions.html").read_text(encoding="utf-8")

    assert "/api/runs" in script
    assert "start-run-form" in markup
    assert "runs-output" in markup
    assert "selected-run-token" in script
    assert "/api/sessions" not in script
