"""Creating and starting notes vaults from the platform (core.source_vaults)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from core import dashboard_auth
from core import source_vaults
from core import sources
from core.api_server import app


@pytest.fixture
def env(monkeypatch, tmp_path):
    """A Source checkout, an empty registry and a vaults folder, all under tmp_path."""
    checkout = tmp_path / "Source"
    checkout.mkdir()
    (checkout / "serve_http.py").write_text("", encoding="utf-8")
    (checkout / "build_index.py").write_text("", encoding="utf-8")
    registry = tmp_path / "sources.yaml"
    registry.write_text("# registry\nsources:\n  team-notes: {url: \"http://127.0.0.1:7801\"}\n", encoding="utf-8")
    monkeypatch.setenv("SMITH_SOURCE_DIR", str(checkout))
    monkeypatch.setenv("SMITH_VAULTS_DIR", str(tmp_path / "vaults"))
    monkeypatch.setenv("SOURCE_REGISTRY", str(registry))
    monkeypatch.setattr(source_vaults._paths, "LOGS_DIR", tmp_path / "logs")

    calls = {"build": [], "launch": []}

    def _run(args, **kwargs):
        calls["build"].append([str(a) for a in args])
        Path(args[args.index("--db") + 1]).write_text("index", encoding="utf-8")
        return MagicMock(returncode=0, stderr="")

    def _popen(args, **kwargs):
        calls["launch"].append({"args": [str(a) for a in args], "env": kwargs["env"]})
        return MagicMock(pid=4321)

    monkeypatch.setattr(source_vaults.subprocess, "run", _run)
    monkeypatch.setattr(source_vaults.subprocess, "Popen", _popen)
    monkeypatch.setattr(source_vaults, "_port_in_use", lambda port: False)
    monkeypatch.setattr(source_vaults, "_healthy", lambda url: bool(calls["launch"]))
    monkeypatch.setattr(source_vaults.time, "sleep", lambda s: None)
    return {"tmp": tmp_path, "registry": registry, "calls": calls, "checkout": checkout}


def test_creating_a_vault_makes_the_folder_indexes_it_starts_it_and_registers_it(env):
    result = source_vaults.create_vault("  Acme-Shop ")

    vault = env["tmp"] / "vaults" / "acme-shop"
    assert result == {"name": "acme-shop", "url": "http://127.0.0.1:7802", "folder": str(vault), "status": "running"}
    assert (vault / "welcome.md").read_text(encoding="utf-8").startswith("---\ntags: [welcome]")
    build, launch = env["calls"]["build"][0], env["calls"]["launch"][0]
    assert build[1].endswith("build_index.py") and build[build.index("--vault") + 1] == str(vault)
    assert launch["args"][1].endswith("serve_http.py") and launch["args"][-2:] == ["--port", "7802"]
    assert launch["env"]["INSTANCE"] == "acme-shop"
    # Registered next to the existing vault, and startable later.
    assert sorted(sources.list_sources()) == ["acme-shop", "team-notes"]
    assert sources.list_sources()["acme-shop"] == {"name": "acme-shop", "url": "http://127.0.0.1:7802"}
    recorded = sources.list_launchable()["acme-shop"]
    assert Path(recorded["vault"]) == vault and recorded["db"].endswith("/.index/acme-shop.sqlite")
    assert source_vaults.startable() == {"acme-shop"}
    assert env["registry"].read_text(encoding="utf-8").startswith("# registry\nsources:\n  team-notes:")


@pytest.mark.parametrize("name", ["", "a b", "../up", "UPPER_case!", "-lead", "x" * 40, "a/b", "naïve"])
def test_a_vault_name_is_a_short_slug(env, name):
    with pytest.raises(source_vaults.VaultError):
        source_vaults.create_vault(name)
    assert env["calls"]["build"] == [] and not (env["tmp"] / "vaults").exists()


def test_a_vault_is_not_created_twice_or_over_existing_notes(env):
    with pytest.raises(source_vaults.VaultError) as taken:
        source_vaults.create_vault("team-notes")
    assert taken.value.status == 409

    existing = env["tmp"] / "vaults" / "old"
    existing.mkdir(parents=True)
    (existing / "mine.md").write_text("keep me", encoding="utf-8")
    with pytest.raises(source_vaults.VaultError):
        source_vaults.create_vault("old")
    assert (existing / "mine.md").read_text(encoding="utf-8") == "keep me"
    assert env["calls"]["build"] == []


def test_a_failed_index_build_leaves_nothing_behind(env, monkeypatch):
    monkeypatch.setattr(source_vaults.subprocess, "run",
                        lambda args, **kw: MagicMock(returncode=1, stderr="Traceback: secret path"))

    with pytest.raises(source_vaults.VaultError) as err:
        source_vaults.create_vault("acme")

    assert "secret path" not in err.value.public        # a fixed message, not process output
    assert not (env["tmp"] / "vaults" / "acme").exists()
    assert "acme" not in sources.list_sources()
    assert env["calls"]["launch"] == []


def test_creating_needs_source_installed(env, monkeypatch):
    monkeypatch.setenv("SMITH_SOURCE_DIR", str(env["tmp"] / "nowhere"))

    assert source_vaults.can_create() is False and source_vaults.startable() == set()
    with pytest.raises(source_vaults.VaultError) as err:
        source_vaults.create_vault("acme")
    assert "not installed" in err.value.public


def test_starting_a_vault_that_is_down_and_leaving_a_running_one_alone(env):
    source_vaults.create_vault("acme")
    env["calls"]["launch"].clear()                      # as after a reboot: registered, not running

    started = source_vaults.start_vault("acme")
    assert started["status"] == "running" and len(env["calls"]["launch"]) == 1
    assert len(env["calls"]["build"]) == 1              # the index is already there: not rebuilt

    again = source_vaults.start_vault("acme")           # now answering
    assert again["status"] == "running" and len(env["calls"]["launch"]) == 1


def test_a_vault_without_a_recorded_folder_cannot_be_started(env):
    with pytest.raises(source_vaults.VaultError) as err:
        source_vaults.start_vault("team-notes")
    assert "sources.yaml" in err.value.public and env["calls"]["launch"] == []


def test_registry_reads_vault_folders_in_both_forms_and_keeps_them_out_of_list_sources(tmp_path):
    registry = tmp_path / "sources.yaml"
    registry.write_text(
        "sources:\n"
        '  one: {url: "http://127.0.0.1:7801", vault: "C:/notes/one", db: "C:/notes/one.sqlite"}\n'
        "  two:\n"
        "    url: http://localhost:7802\n"
        "    vault: /srv/notes/two\n"
        '  three: {url: "http://127.0.0.1:7803"}\n',
        encoding="utf-8",
    )

    assert sources.list_launchable(registry) == {
        "one": {"name": "one", "url": "http://127.0.0.1:7801", "vault": "C:/notes/one", "db": "C:/notes/one.sqlite"},
        "two": {"name": "two", "url": "http://localhost:7802", "vault": "/srv/notes/two"},
    }
    assert all(set(meta) == {"name", "url"} for meta in sources.list_sources(registry).values())


def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("SMITH_DATABASE_URL", f"sqlite:///{tmp_path / 'runs.db'}")
    monkeypatch.setenv("SMITH_DASHBOARD_AUTH", "1")
    monkeypatch.delenv("SMITH_SINGLE_RUN", raising=False)
    return TestClient(app), {"Authorization": f"Bearer {dashboard_auth.mint_operator_token()}"}


def test_the_platform_creates_and_starts_vaults_for_the_operator_only(env, monkeypatch):
    client, operator = _client(monkeypatch, env["tmp"])

    assert client.post("/api/knowledge/vaults", json={"name": "acme"}).status_code in (401, 403)
    run_token = {"Authorization": f"Bearer {dashboard_auth.mint_run_token('run-x')}"}
    assert client.post("/api/knowledge/vaults", json={"name": "acme"}, headers=run_token).status_code == 403
    assert env["calls"]["build"] == []

    created = client.post("/api/knowledge/vaults", json={"name": "acme"}, headers=operator)
    assert created.status_code == 200
    assert created.json() == {"ok": True, "name": "acme", "status": "running"}

    bad = client.post("/api/knowledge/vaults", json={"name": "../x"}, headers=operator)
    assert bad.status_code == 400 and "lowercase" in bad.json()["error"]
    assert client.post("/api/knowledge/vaults", json={"name": "acme"}, headers=operator).status_code == 409

    assert client.post("/api/knowledge/acme/start", headers=operator).json()["status"] == "running"
    assert client.post("/api/knowledge/nope/start", headers=operator).status_code == 404
    assert client.post("/api/knowledge/team-notes/start", headers=operator).status_code == 409
    assert client.post("/api/knowledge/acme/start", headers=run_token).status_code == 403


def test_the_vault_list_says_what_can_be_created_and_started(env, monkeypatch):
    client, operator = _client(monkeypatch, env["tmp"])
    source_vaults.create_vault("acme")

    async def _describe(name, url):
        return {"name": name, "url": url, "reachable": False, "ready": False, "instance": "", "notes": None}

    monkeypatch.setattr("core.api_server.routes.knowledge_routes._describe", _describe)
    listing = client.get("/api/knowledge", headers=operator).json()

    assert listing["can_create"] is True
    assert {s["name"]: s["startable"] for s in listing["sources"]} == {"acme": True, "team-notes": False}
    assert "vault" not in str(listing) and "folder" not in str(listing)     # no local paths in the list
