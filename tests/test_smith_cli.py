import json

import smith_cli


def test_smith_start_prints_started(monkeypatch, capsys):
    monkeypatch.setattr(
        "control_plane.orchestrator.start_control_plane",
        lambda: {"status": "started", "dashboard_url": "http://127.0.0.1:7777"},
    )
    assert smith_cli.main(["start"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "started"


def test_smith_status_prints_health(monkeypatch, capsys):
    monkeypatch.setattr(
        "control_plane.orchestrator.control_plane_status",
        lambda: {"database": "healthy", "dashboard": "running", "orchestrator": "running"},
    )
    assert smith_cli.main(["status"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["database"] == "healthy"


def test_smith_stop_prints_stopped(monkeypatch, capsys):
    monkeypatch.setattr(
        "control_plane.orchestrator.stop_control_plane",
        lambda: {"status": "stopped"},
    )
    assert smith_cli.main(["stop"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "stopped"
