"""
Tool results summary
====================
Turns the raw tool artifacts of a scan into "what did each tool find?", so an
operator can see the ports, subdomains, endpoints, technologies, template hits
and leaked secrets without reading the logs.

Sources (all per scan, all read-only):

* ``artifacts/<tool>_<HHMMSS>_<8hex>.txt`` — the raw output every tool run stores
  (``mcp_server.scan_engine.artifacts.store_artifact``).
* ``quick_log.json`` — one ``TOOL`` entry per call, carrying the target and, for
  ``kali``, the command line. Artifacts do not record their command, so each
  artifact is paired with the latest same-tool entry at or before it. That is a
  best-effort link: it is exact for sequential calls and may mislabel a run when
  two calls of the same tool overlap.
* ``session.known_assets`` — what the scan engine itself extracted.

Parsers are deliberately forgiving: a tool whose output cannot be parsed still
gets a card listing its runs, with a link to the raw output.

Secret values are never returned. Secret scanners are reduced to
detector/location, and raw-output views go through the logger's redaction.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

_ARTIFACT_RE = re.compile(r"^(?P<tool>.+)_(?P<hms>\d{6})_(?P<uid>[0-9a-f]{8})$")
_MAX_ARTIFACTS = 600           # newest N artifacts considered per request
_MAX_ROWS = 500                # rows returned per tool
_MAX_PARSE_BYTES = 2_000_000   # per artifact
_RAW_VIEW_CHARS = 200_000

# Display order = the order an engagement usually unfolds in.
_TOOL_META: dict[str, dict] = {
    "subfinder":    {"label": "subfinder",     "purpose": "Subdomains discovered for the target domain."},
    "naabu":        {"label": "naabu",         "purpose": "Open ports found by the fast port scan."},
    "nmap":         {"label": "nmap",          "purpose": "Open ports and the services behind them."},
    "httpx":        {"label": "httpx",         "purpose": "Live web servers, their titles and technologies."},
    "spider":       {"label": "spider",        "purpose": "URLs and endpoints discovered by crawling."},
    "ffuf":         {"label": "ffuf",          "purpose": "Hidden paths found by brute-forcing names."},
    "nuclei":       {"label": "nuclei",        "purpose": "Known-vulnerability and misconfiguration templates that matched."},
    "semgrep":      {"label": "semgrep",       "purpose": "Suspicious code patterns found in the source."},
    "trufflehog":   {"label": "trufflehog",    "purpose": "Secrets found in the source (values are not shown)."},
    "mobsfscan":    {"label": "mobsfscan",     "purpose": "Mobile source-code issues."},
    "mobsf":        {"label": "MobSF",         "purpose": "Mobile app static analysis."},
    "garak":        {"label": "garak",         "purpose": "Automated LLM vulnerability probes."},
    "redteam":      {"label": "redteam",       "purpose": "AI red-team attack runs."},
    "metasploit":   {"label": "metasploit",    "purpose": "Exploit modules that were run."},
    "exec_sandbox": {"label": "sandbox",       "purpose": "Target code built or run in the sandbox to confirm a finding."},
    "sweep":        {"label": "coverage sweep", "purpose": "Automated injection probes across pending coverage cells."},
    "kali":         {"label": "Kali commands", "purpose": "Commands Smith ran in the Kali container, grouped by program."},
    "http_request": {"label": "HTTP requests", "purpose": "Individual HTTP requests Smith sent."},
}
_ORDER = {name: i for i, name in enumerate(_TOOL_META)}

_cache: dict[str, tuple[float, int, dict]] = {}   # path -> (mtime, size, parsed)


# ── small helpers ────────────────────────────────────────────────────────────

def _json_lines(text: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def _json_doc(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _path_of(url: str) -> str:
    try:
        parts = urlsplit(url)
        return (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    except ValueError:
        return url


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


# ── per-tool parsers: text -> (rows, columns) ───────────────────────────────
# A row is a flat dict of display strings. `columns` is [[key, label], ...].

def _parse_naabu(text: str):
    rows = [{"host": str(o.get("host") or o.get("ip") or ""), "port": str(o.get("port") or ""),
             "protocol": str(o.get("protocol") or "tcp")} for o in _json_lines(text) if o.get("port")]
    if not rows:  # plain "host:port" lines
        for line in text.splitlines():
            m = re.fullmatch(r"\s*([\w.\-:\[\]]+):(\d{1,5})\s*", line)
            if m:
                rows.append({"host": m.group(1), "port": m.group(2), "protocol": "tcp"})
    return rows, [["host", "Host"], ["port", "Port"], ["protocol", "Protocol"]]


def _parse_nmap(text: str):
    rows: list[dict] = []
    # Grepable output (-oG -): "Host: 1.2.3.4 (name)\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http//nginx/"
    for line in text.splitlines():
        m = re.match(r"Host:\s+(\S+)(?:\s+\(([^)]*)\))?.*?Ports:\s+(.*?)(?:\t|$)", line)
        if not m:
            continue
        host = m.group(2) or m.group(1)
        for entry in m.group(3).split(","):
            f = entry.strip().split("/")
            if len(f) >= 5 and f[1] == "open":
                rows.append({"host": host, "port": f[0], "protocol": f[2], "service": f[4],
                             "version": f[6] if len(f) > 6 else ""})
    if not rows:  # normal output: "80/tcp open http nginx 1.2"
        host = ""
        for line in text.splitlines():
            h = re.match(r"Nmap scan report for (.+)", line)
            if h:
                host = h.group(1).strip()
                continue
            m = re.match(r"(\d{1,5})/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                rows.append({"host": host, "port": m.group(1), "protocol": m.group(2),
                             "service": m.group(3), "version": m.group(4).strip()})
    return rows, [["host", "Host"], ["port", "Port"], ["protocol", "Protocol"], ["service", "Service"], ["version", "Version"]]


def _parse_subfinder(text: str):
    names = [str(o.get("host") or "") for o in _json_lines(text) if o.get("host")]
    if not names:
        names = [ln.strip() for ln in text.splitlines()
                 if re.fullmatch(r"[A-Za-z0-9_.\-]+\.[A-Za-z]{2,}", ln.strip())]
    return [{"subdomain": n} for n in names], [["subdomain", "Subdomain"]]


def _parse_httpx(text: str):
    rows = []
    for o in _json_lines(text):
        if not o.get("url"):
            continue
        rows.append({"url": str(o.get("url")), "status": str(o.get("status_code") or ""),
                     "title": str(o.get("title") or ""), "server": str(o.get("webserver") or ""),
                     "technologies": ", ".join(o.get("tech") or [])})
    return rows, [["url", "URL"], ["status", "Status"], ["title", "Title"], ["server", "Server"], ["technologies", "Technologies"]]


def _parse_spider(text: str):
    rows = []
    crawler = ""
    for line in text.splitlines():
        line = line.strip()
        h = re.fullmatch(r"=+\s*(.+?)\s*=+", line)
        if h:
            crawler = h.group(1)
            continue
        m = re.search(r"https?://[^\s\"'<>]+", line)
        if m:
            url = m.group(0).rstrip(",;")
            rows.append({"path": _path_of(url), "url": url, "found_by": crawler})
    return rows, [["path", "Path"], ["url", "Full URL"], ["found_by", "Found by"]]


def _parse_ffuf(text: str):
    rows = []
    doc = _json_doc(text)
    results = doc.get("results") if isinstance(doc, dict) else None
    if isinstance(results, list):
        for r in results:
            if isinstance(r, dict):
                rows.append({"path": _path_of(str(r.get("url") or "")) or str((r.get("input") or {}).get("FUZZ") or ""),
                             "status": str(r.get("status") or ""), "size": str(r.get("length") or ""),
                             "url": str(r.get("url") or "")})
    else:  # "admin [Status: 200, Size: 1234, ...]"
        for line in text.splitlines():
            m = re.match(r"\s*(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
            if m:
                rows.append({"path": m.group(1), "status": m.group(2), "size": m.group(3), "url": ""})
    return rows, [["path", "Path"], ["status", "Status"], ["size", "Size"]]


def _parse_nuclei(text: str):
    items: list[dict] = []
    doc = _json_doc(text)
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        items = [f for f in doc["findings"] if isinstance(f, dict)]
    if not items:
        items = _json_lines(text)
    rows = []
    for f in items:
        info = f.get("info") if isinstance(f.get("info"), dict) else {}
        template = f.get("template-id") or f.get("template_id") or f.get("template") or f.get("id") or ""
        if not template and not f.get("matched-at") and not f.get("matched_at"):
            continue
        rows.append({"severity": str(info.get("severity") or f.get("severity") or "").lower(),
                     "template": str(template), "name": str(info.get("name") or f.get("name") or ""),
                     "matched": str(f.get("matched-at") or f.get("matched_at") or f.get("host") or "")})
    return rows, [["severity", "Severity"], ["template", "Template"], ["name", "Name"], ["matched", "Matched at"]]


def _parse_semgrep(text: str):
    doc = _json_doc(text)
    results = doc.get("results") if isinstance(doc, dict) else None
    rows = []
    for r in results or []:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        rows.append({"severity": str(extra.get("severity") or "").lower(),
                     "rule": str(r.get("check_id") or "").split(".")[-1],
                     "location": f"{r.get('path', '')}:{start.get('line', '')}".rstrip(":"),
                     "message": str(extra.get("message") or "")[:240]})
    return rows, [["severity", "Severity"], ["rule", "Rule"], ["location", "Location"], ["message", "Message"]]


def _parse_trufflehog(text: str):
    """Detector and location only — never the secret value."""
    rows = []
    for o in _json_lines(text):
        if not o.get("DetectorName") and not o.get("detector_name"):
            continue
        data = ((o.get("SourceMetadata") or {}).get("Data") or {}) if isinstance(o.get("SourceMetadata"), dict) else {}
        loc = ""
        for src in data.values() if isinstance(data, dict) else []:
            if isinstance(src, dict):
                loc = f"{src.get('file', '')}:{src.get('line', '')}".rstrip(":")
                break
        rows.append({"detector": str(o.get("DetectorName") or o.get("detector_name")),
                     "verified": "yes" if o.get("Verified") else "not checked",
                     "location": loc})
    return rows, [["detector", "Secret type"], ["location", "Location"], ["verified", "Verified live"]]


def _parse_http_request(text: str):
    doc = _json_doc(text)
    if not isinstance(doc, dict) or "status" not in doc:
        return [], [["status", "Status"], ["url", "Request"], ["size", "Response size"]]
    headers = doc.get("headers") if isinstance(doc.get("headers"), dict) else {}
    body = doc.get("body")
    size = headers.get("Content-Length") or (len(body) if isinstance(body, str) else "")
    return ([{"status": str(doc.get("status")), "url": "", "size": str(size),
              "type": str(headers.get("Content-Type") or "").split(";")[0]}],
            [["status", "Status"], ["url", "Request"], ["type", "Content type"], ["size", "Response size"]])


_PARSERS = {
    "naabu": _parse_naabu, "nmap": _parse_nmap, "subfinder": _parse_subfinder, "httpx": _parse_httpx,
    "spider": _parse_spider, "ffuf": _parse_ffuf, "nuclei": _parse_nuclei, "semgrep": _parse_semgrep,
    "mobsfscan": _parse_semgrep, "trufflehog": _parse_trufflehog, "http_request": _parse_http_request,
}

# What identifies a row as "the same result" across repeated runs of a tool.
_DEDUP_KEYS = {
    "naabu": ("host", "port", "protocol"), "nmap": ("host", "port", "protocol"), "subfinder": ("subdomain",),
    "httpx": ("url",), "spider": ("path",), "ffuf": ("path", "status"), "nuclei": ("template", "matched"),
    "semgrep": ("rule", "location"), "mobsfscan": ("rule", "location"), "trufflehog": ("detector", "location"),
}

_HEADLINES = {
    "naabu": lambda rows: f"{_plural(len(rows), 'open port')} on {_plural(len({r['host'] for r in rows}), 'host')}",
    "nmap": lambda rows: f"{_plural(len(rows), 'open port')} on {_plural(len({r['host'] for r in rows}), 'host')}",
    "subfinder": lambda rows: _plural(len(rows), "subdomain"),
    "httpx": lambda rows: _plural(len(rows), "live web server"),
    "spider": lambda rows: _plural(len(rows), "unique URL"),
    "ffuf": lambda rows: _plural(len(rows), "path"),
    "nuclei": lambda rows: _plural(len(rows), "template match", "template matches"),
    "semgrep": lambda rows: _plural(len(rows), "code finding"),
    "mobsfscan": lambda rows: _plural(len(rows), "code finding"),
    "trufflehog": lambda rows: _plural(len(rows), "secret"),
}


# ── artifacts ────────────────────────────────────────────────────────────────

def _list_artifacts(artifacts_dir: Path) -> list[dict]:
    if not artifacts_dir.is_dir():
        return []
    found = []
    for p in artifacts_dir.glob("*.txt"):
        m = _ARTIFACT_RE.match(p.stem)
        if not m:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        found.append({"id": p.stem, "tool": m.group("tool"), "path": p, "mtime": st.st_mtime, "size": st.st_size})
    found.sort(key=lambda a: a["mtime"], reverse=True)
    return found[:_MAX_ARTIFACTS]


def _parse_artifact(art: dict) -> dict:
    """Parsed view of one artifact, cached on (mtime, size)."""
    key = str(art["path"])
    hit = _cache.get(key)
    if hit and hit[0] == art["mtime"] and hit[1] == art["size"]:
        return hit[2]
    try:
        with art["path"].open("r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(_MAX_PARSE_BYTES)
    except OSError:
        text = ""
    parser = _PARSERS.get(art["tool"])
    rows, columns = ([], [])
    if parser:
        try:
            rows, columns = parser(text)
        except Exception:      # a malformed artifact must never break the page
            rows, columns = [], []
    parsed = {"rows": rows, "columns": columns, "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0)}
    if len(_cache) > 4000:
        _cache.clear()
    _cache[key] = (art["mtime"], art["size"], parsed)
    return parsed


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _calls_by_tool(quick_log: list[dict]) -> dict[str, list[tuple[float, dict]]]:
    calls: dict[str, list[tuple[float, dict]]] = {}
    for e in quick_log or []:
        if not isinstance(e, dict) or e.get("type") not in ("TOOL", "SPIDER"):
            continue
        name = "spider" if e.get("type") == "SPIDER" else str(e.get("name") or "")
        try:
            ts = datetime.fromisoformat(str(e.get("ts"))).timestamp()
        except ValueError:
            continue
        calls.setdefault(name, []).append((ts, e))
    for lst in calls.values():
        lst.sort(key=lambda c: c[0])
    return calls


_MATCH_WINDOW_S = 1800     # a call is not paired with an artifact written >30 min later


def _pair_calls(artifacts: list[dict], calls: dict[str, list[tuple[float, dict]]]) -> dict[str, dict]:
    """Pair each artifact with the call that produced it: artifact id -> log entry.

    One call yields one artifact, so the pairing is one-to-one: walking both lists
    in time order, an artifact takes the latest not-yet-used call of its tool that
    started at or before it (and not implausibly long before). Artifacts without
    a recorded call are simply left unpaired.
    """
    paired: dict[str, dict] = {}
    per_tool: dict[str, list[dict]] = {}
    for art in artifacts:
        per_tool.setdefault(art["tool"], []).append(art)
    for tool, arts in per_tool.items():
        pending = list(calls.get(tool, []))
        for art in sorted(arts, key=lambda a: a["mtime"]):
            usable = [i for i, (ts, _) in enumerate(pending)
                      if ts <= art["mtime"] + 2 and art["mtime"] - ts <= _MATCH_WINDOW_S]
            if usable:
                paired[art["id"]] = pending.pop(usable[-1])[1]
    return paired


# Wrappers run another program (keep reading the same command); builtins and
# keywords are not interesting themselves (skip to the next simple command).
_SHELL_WRAPPERS = {"sudo", "time", "timeout", "nohup", "env", "exec", "xargs", "bash", "sh", "-c",
                   "then", "do", "else", "if"}
_SHELL_BUILTINS = {"echo", "printf", "cd", "export", "set", "sleep", "true", "done", "fi"}


def _program(command: str) -> str:
    """The program a Kali command line runs.

    Splits the line into simple commands and returns the first word that is a
    real program — skipping loop headers, env assignments, wrappers (sudo,
    timeout) and shell noise (echo, cd, sleep).
    """
    # `for x in a b c; do <program> ...` — the program is what the loop runs.
    command = re.sub(r"\b(?:for|while|until)\b[^;]*;\s*do\b", " ", command)
    for simple in re.split(r"\|\||&&|[;|&\n]", command):
        for token in simple.split():
            token = token.strip("()\"'`")
            if not token or token in _SHELL_WRAPPERS:
                continue
            if token in _SHELL_BUILTINS:
                break                         # `cd /tmp`, `echo ...` — look at the next command
            if re.fullmatch(r"[A-Za-z_]\w*=.*", token) or re.fullmatch(r"[\d.]+[smh]?", token):
                continue                      # VAR=value, or a timeout duration
            name = token.rsplit("/", 1)[-1]
            if re.fullmatch(r"[A-Za-z][\w.+\-]*", name):
                return name[:32]
            break                             # not a program word: try the next simple command
    return "shell"


# ── public API ───────────────────────────────────────────────────────────────

def summarize(artifacts_dir: Path, quick_log: list[dict] | None = None, known_assets: dict | None = None) -> dict:
    """Build the per-tool results summary for one scan."""
    calls = _calls_by_tool(quick_log or [])
    by_tool: dict[str, dict] = {}

    artifacts = _list_artifacts(artifacts_dir)
    paired = _pair_calls(artifacts, calls)
    for art in artifacts:
        tool = art["tool"]
        parsed = _parse_artifact(art)
        call = paired.get(art["id"], {})
        command = str(call.get("command") or "")
        group, label = tool, None
        if tool == "kali":
            # Group Kali runs by the program they ran; runs whose command was not
            # recorded stay together under the generic card.
            program = _program(command) if command else ""
            group, label = (f"kali:{program}", program) if program else ("kali", None)
        card = by_tool.setdefault(group, {"tool": group, "base_tool": tool, "label": label, "runs": [], "rows": [],
                                         "columns": parsed["columns"], "_seen": set()})
        if parsed["columns"] and not card["columns"]:
            card["columns"] = parsed["columns"]
        run = {"artifact_id": art["id"], "time": _iso(art["mtime"]), "target": str(call.get("target") or ""),
               "command": command, "lines": parsed["lines"], "results": len(parsed["rows"]),
               "timed_out": bool(call.get("timed_out")), "error": str(call.get("error") or "")[:200]}
        card["runs"].append(run)
        dedup = _DEDUP_KEYS.get(tool)
        for row in parsed["rows"]:
            row = dict(row)
            if tool == "http_request" and not row.get("url"):
                row["url"] = run["target"]
            if dedup:
                key = tuple(row.get(k, "") for k in dedup)
                if key in card["_seen"]:
                    continue
                card["_seen"].add(key)
            row["artifact_id"] = art["id"]
            row["time"] = run["time"]
            card["rows"].append(row)

    tools = []
    for group, card in by_tool.items():
        base = card["base_tool"]
        meta = _TOOL_META.get(base, {"label": base, "purpose": "Raw output of each run is available below."})
        rows = card["rows"]
        headline_fn = _HEADLINES.get(base)
        if rows and headline_fn:
            headline = headline_fn(rows)
        elif base == "kali":
            headline = _plural(len(card["runs"]), "command")
        elif base == "http_request":
            headline = _plural(len(card["runs"]), "request")
        elif base in _PARSERS:
            headline = "Nothing found"
        else:
            headline = _plural(len(card["runs"]), "run")
        tools.append({
            "tool": group, "base_tool": base,
            "label": (f"{card['label']} (Kali)" if card["label"] else meta["label"]),
            "purpose": ("Commands Smith ran with this program in the Kali container." if card["label"]
                        else meta["purpose"]),
            "headline": headline, "parsed": base in _PARSERS,
            "columns": card["columns"], "rows": rows[:_MAX_ROWS], "total_rows": len(rows),
            "runs": card["runs"][:200], "total_runs": len(card["runs"]),
            "last_run": card["runs"][0]["time"] if card["runs"] else "",
        })
    tools.sort(key=lambda t: (_ORDER.get(t["base_tool"], 50), t["base_tool"] != "kali" or -t["total_runs"], t["label"]))

    ka = known_assets if isinstance(known_assets, dict) else {}
    ports = sorted({f"{p.get('host', '')}:{p.get('port', '')}" for p in ka.get("ports") or [] if isinstance(p, dict)})
    overview = {
        "domains": [str(d) for d in (ka.get("domains") or [])][:100],
        "ips": [str(d) for d in (ka.get("ips") or [])][:100],
        "ports": ports[:200],
        "technologies": [str(t) for t in (ka.get("technologies") or [])][:100],
        "endpoints": [str(e) if not isinstance(e, dict) else str(e.get("path") or e.get("url") or "") for e in (ka.get("endpoints") or [])][:500],
        # Counts only — credentials and tokens are never sent to the browser from here.
        "credentials": len(ka.get("credentials") or []),
        "auth_tokens": len(ka.get("auth_tokens") or []),
    }
    return {"overview": overview, "tools": tools,
            "total_runs": sum(t["total_runs"] for t in tools)}


def read_artifact(artifacts_dir: Path, artifact_id: str) -> dict | None:
    """Raw output of one artifact (secret-redacted, bounded). ``None`` if unknown.

    The file is looked up among the directory's own entries; the caller-supplied
    id is never joined into a path.
    """
    wanted = str(artifact_id or "")
    for art in _list_artifacts(artifacts_dir):
        if art["id"] == wanted:
            try:
                with art["path"].open("r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read(_RAW_VIEW_CHARS + 1)
            except OSError:
                return None
            truncated = len(text) > _RAW_VIEW_CHARS
            from core.logger import _redact
            return {"artifact_id": art["id"], "tool": art["tool"], "time": _iso(art["mtime"]),
                    "size": art["size"], "truncated": truncated, "text": _redact(text[:_RAW_VIEW_CHARS])}
    return None
