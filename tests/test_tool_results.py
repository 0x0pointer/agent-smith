"""core.tool_results — per-tool results summary for the dashboard's Tool Results page."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core import tool_results


def _artifact(root: Path, tool: str, hms: str, uid: str, text: str, when: float) -> str:
    root.mkdir(parents=True, exist_ok=True)
    name = f"{tool}_{hms}_{uid}"
    path = root / f"{name}.txt"
    path.write_text(text, encoding="utf-8")
    os.utime(path, (when, when))
    return name


def _ts(when: float) -> str:
    return datetime.fromtimestamp(when, tz=timezone.utc).isoformat()


def _card(summary: dict, tool: str) -> dict:
    return next(t for t in summary["tools"] if t["tool"] == tool)


def test_ports_are_parsed_and_deduplicated_across_runs(tmp_path):
    base = 1_800_000_000.0
    line = lambda port: json.dumps({"ip": "10.0.0.5", "port": port, "protocol": "tcp"})
    _artifact(tmp_path, "naabu", "100000", "aaaaaaaa", "\n".join([line(80), line(443)]), base)
    _artifact(tmp_path, "naabu", "100100", "bbbbbbbb", "\n".join([line(80), line(8080)]), base + 60)

    card = _card(tool_results.summarize(tmp_path), "naabu")

    assert card["total_runs"] == 2
    assert sorted(r["port"] for r in card["rows"]) == ["443", "80", "8080"]
    assert card["headline"] == "3 open ports on 1 host"


def test_nmap_grepable_and_normal_output(tmp_path):
    grepable = "Host: 10.0.0.5 (db.example)\tPorts: 22/open/tcp//ssh//OpenSSH 9.6/, 5432/open/tcp//postgresql///, 81/closed/tcp//x///\n"
    normal = "Nmap scan report for web.example\nPORT   STATE SERVICE VERSION\n80/tcp open  http    nginx 1.25\n"
    _artifact(tmp_path, "nmap", "100000", "aaaaaaaa", grepable, 1_800_000_000.0)
    _artifact(tmp_path, "nmap", "100100", "bbbbbbbb", normal, 1_800_000_060.0)

    rows = {(r["host"], r["port"]): r for r in _card(tool_results.summarize(tmp_path), "nmap")["rows"]}

    assert set(rows) == {("db.example", "22"), ("db.example", "5432"), ("web.example", "80")}
    assert rows[("db.example", "22")]["service"] == "ssh"
    assert rows[("web.example", "80")]["version"] == "nginx 1.25"


def test_spider_subfinder_httpx_and_nuclei(tmp_path):
    t = 1_800_000_000.0
    _artifact(tmp_path, "spider", "100000", "aaaaaaaa",
              "=== katana ===\nhttp://t.example/login\nhttp://t.example/login\nhttp://t.example/api/users?id=1\n", t)
    _artifact(tmp_path, "subfinder", "100001", "bbbbbbbb", "api.t.example\nmail.t.example\nnot a host\n", t + 1)
    _artifact(tmp_path, "httpx", "100002", "cccccccc",
              json.dumps({"url": "http://t.example", "status_code": 200, "title": "Shop", "webserver": "nginx", "tech": ["Flask"]}), t + 2)
    _artifact(tmp_path, "nuclei", "100003", "dddddddd",
              json.dumps({"template-id": "exposed-git", "info": {"severity": "HIGH", "name": "Git exposed"}, "matched-at": "http://t.example/.git/"}), t + 3)

    s = tool_results.summarize(tmp_path)

    assert [r["path"] for r in _card(s, "spider")["rows"]] == ["/login", "/api/users?id=1"]
    assert {r["subdomain"] for r in _card(s, "subfinder")["rows"]} == {"api.t.example", "mail.t.example"}
    assert _card(s, "httpx")["rows"][0]["technologies"] == "Flask"
    nuclei = _card(s, "nuclei")["rows"][0]
    assert (nuclei["severity"], nuclei["template"]) == ("high", "exposed-git")
    # Cards follow the order an engagement unfolds in.
    order = [t["tool"] for t in s["tools"]]
    assert order.index("subfinder") < order.index("httpx") < order.index("spider") < order.index("nuclei")


def test_secret_values_never_reach_the_summary_or_the_raw_view(tmp_path):
    secret = "zz-not-a-real-secret-value-zz"
    finding = {"DetectorName": "AWS", "Verified": False, "Raw": secret,
               "SourceMetadata": {"Data": {"Filesystem": {"file": "app/config.py", "line": 12}}}}
    art = _artifact(tmp_path, "trufflehog", "100000", "aaaaaaaa", json.dumps(finding), 1_800_000_000.0)
    _artifact(tmp_path, "kali", "100100", "bbbbbbbb", "Authorization: Bearer abc.def.ghi\npassword=hunter2\n", 1_800_000_060.0)

    s = tool_results.summarize(tmp_path, known_assets={"credentials": [{"username": "a", "password": "p"}], "auth_tokens": [{"value": "zzTOKENVALUEzz"}]})

    row = _card(s, "trufflehog")["rows"][0]
    assert (row["detector"], row["location"]) == ("AWS", "app/config.py:12")
    assert secret not in json.dumps(s)
    assert s["overview"]["credentials"] == 1 and s["overview"]["auth_tokens"] == 1
    assert "hunter2" not in json.dumps(s) and "zzTOKENVALUEzz" not in json.dumps(s)
    raw = tool_results.read_artifact(tmp_path, "kali_100100_bbbbbbbb")
    assert "hunter2" not in raw["text"] and "abc.def.ghi" not in raw["text"]
    assert tool_results.read_artifact(tmp_path, art)["tool"] == "trufflehog"


def test_kali_runs_are_grouped_by_program_using_the_recorded_command(tmp_path):
    t = 1_800_000_000.0
    _artifact(tmp_path, "kali", "100005", "aaaaaaaa", "sqlmap output\n", t + 5)
    _artifact(tmp_path, "kali", "100105", "bbbbbbbb", "nikto output\n", t + 65)
    _artifact(tmp_path, "kali", "110000", "cccccccc", "orphan output\n", t + 7200)   # no recorded call
    log = [
        {"type": "TOOL", "name": "kali", "command": "sqlmap -u http://t/x?id=1 --batch", "ts": _ts(t)},
        {"type": "TOOL", "name": "kali", "command": "for h in a b; do nikto -h $h; done", "ts": _ts(t + 60)},
    ]

    s = tool_results.summarize(tmp_path, log)

    assert _card(s, "kali:sqlmap")["runs"][0]["command"].startswith("sqlmap -u")
    assert _card(s, "kali:nikto")["total_runs"] == 1
    # One call pairs with one artifact; the late orphan is not mislabelled.
    orphan = _card(s, "kali")
    assert orphan["total_runs"] == 1 and orphan["runs"][0]["command"] == ""


def test_unknown_tools_and_malformed_output_still_get_a_card(tmp_path):
    _artifact(tmp_path, "mystery_tool", "100000", "aaaaaaaa", "some output\nmore\n", 1_800_000_000.0)
    _artifact(tmp_path, "naabu", "100100", "bbbbbbbb", "{not json\n\x00garbage", 1_800_000_060.0)
    (tmp_path / "not-an-artifact.txt").write_text("ignored")

    s = tool_results.summarize(tmp_path)

    assert _card(s, "mystery_tool")["headline"] == "1 run"
    assert _card(s, "naabu")["headline"] == "Nothing found"
    assert len(s["tools"]) == 2
    assert tool_results.summarize(tmp_path / "missing") == {
        "overview": {"domains": [], "ips": [], "ports": [], "technologies": [], "endpoints": [], "credentials": 0, "auth_tokens": 0},
        "tools": [], "total_runs": 0}


def test_raw_view_only_serves_files_listed_in_the_directory(tmp_path):
    (tmp_path / "secret.txt").write_text("top secret")
    arts = tmp_path / "artifacts"
    _artifact(arts, "kali", "100000", "aaaaaaaa", "ok\n", 1_800_000_000.0)

    assert tool_results.read_artifact(arts, "../secret") is None
    assert tool_results.read_artifact(arts, "kali_100000_aaaaaaaa/../../secret") is None
    assert tool_results.read_artifact(arts, "") is None
    assert tool_results.read_artifact(arts, "kali_100000_aaaaaaaa")["text"] == "ok\n"


def test_program_detection_skips_shell_noise():
    program = tool_results._program
    assert program('for h in a b; do echo "=== $h ==="; curl -s http://$h:5000/; done') == "curl"
    assert program("FOO=bar timeout 30 /usr/bin/nmap -sV host") == "nmap"
    assert program("cd /tmp && python3 exploit.py") == "python3"
    assert program("echo hi") == "shell"
