"""
Parser-first summarizers — extract structured facts from raw tool output.

Each summarizer returns a SummaryResult. If a tool has no dedicated summarizer,
the generic fallback is used (first N lines + tail).

Adding a new summarizer: define a function `_summarize_<tool>(raw, ctx) -> SummaryResult`
and register it in _SUMMARIZERS.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SummaryResult:
    summary: str = ""
    facts: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    recommended: list[str] = field(default_factory=list)


def summarize(tool: str, raw: str, ctx: dict) -> SummaryResult:
    """Dispatch to tool-specific summarizer or fall back to generic."""
    fn = _SUMMARIZERS.get(tool, _summarize_generic)
    return fn(raw, ctx)


# ---------------------------------------------------------------------------
# httpx summarizer
# ---------------------------------------------------------------------------

def _parse_httpx_json_line(line: str, url: str) -> dict | None:
    """Parse a single httpx JSON line. Returns parsed fields dict or None on failure."""
    try:
        data = json.loads(line)
        return {
            "status": data.get("status_code") or data.get("status-code"),
            "tech": data.get("tech", []),
            "title": data.get("title", ""),
            "content_type": data.get("content_type", data.get("content-type", "")),
            "server": data.get("webserver", data.get("server", "")),
            "cdn_or_waf": data.get("cdn", "") or data.get("waf", ""),
            "url": data.get("url", url),
        }
    except json.JSONDecodeError:
        return None


def _parse_httpx_text_line(line: str, url: str) -> dict | None:
    """Parse a single httpx text-mode line. Returns parsed fields dict or None on no match."""
    m = re.match(r'(https?://\S+)\s+\[(\d+)\]', line)
    if not m:
        return None
    brackets = re.findall(r'\[([^\]]+)\]', line)
    return {
        "status": int(m.group(2)),
        "url": m.group(1),
        "server": brackets[1] if len(brackets) > 1 else "",
        "content_type": brackets[2] if len(brackets) > 2 else "",
        "title": brackets[3] if len(brackets) > 3 else "",
        "tech": [],
        "cdn_or_waf": "",
    }


def _build_httpx_facts(result: SummaryResult, status: Any, server: str, content_type: str, title: str, tech: Any, cdn_or_waf: str) -> None:
    """Append extracted fields to result.facts."""
    if status:
        result.facts.append(f"Status: {status}")
    if server:
        result.facts.append(f"Server: {server}")
    if content_type:
        result.facts.append(f"Content-Type: {content_type}")
    if title:
        result.facts.append(f"Title: {title}")
    if tech:
        result.facts.append(f"Tech: {', '.join(tech) if isinstance(tech, list) else tech}")
    if cdn_or_waf:
        result.facts.append(f"CDN/WAF: {cdn_or_waf}")


def _find_parsed_httpx_line(lines: list[str], url: str) -> dict | None:
    """Return the first successfully parsed line from httpx output, or None."""
    for line in lines:
        line = line.strip()
        parsed = (
            _parse_httpx_json_line(line, url)
            if line.startswith("{")
            else _parse_httpx_text_line(line, url)
        )
        if parsed:
            return parsed
    return None


def _build_httpx_summary(result: "SummaryResult", url: str, status: object, server: str) -> None:
    """Populate result.summary and anomalies based on parsed httpx status."""
    if status:
        result.summary = f"{url} is live (HTTP {status})"
        if server:
            result.summary += f", server: {server}"
    else:
        result.summary = f"httpx scan of {url} — could not parse status"
        result.anomalies.append("Could not parse httpx output format")


def _summarize_httpx(raw: str, ctx: dict) -> SummaryResult:
    """Parse httpx output to extract tech stack, status, WAF, headers."""
    result = SummaryResult()
    url = ctx.get("url", "")
    parsed = _find_parsed_httpx_line(raw.strip().splitlines(), url)

    if parsed:
        status       = parsed["status"]
        url          = parsed["url"]
        server       = parsed["server"]
        tech         = parsed["tech"]
        content_type = parsed["content_type"]
        title        = parsed["title"]
        cdn_or_waf   = parsed["cdn_or_waf"]
    else:
        status = None
        server = tech = content_type = title = cdn_or_waf = ""

    _build_httpx_summary(result, url, status, server)
    _build_httpx_facts(result, status, server, content_type, title, tech, cdn_or_waf)

    result.evidence = {
        "url": url,
        "status": status,
        "server": server,
        "tech": tech,
    }

    result.recommended.append("Run scan(tool='spider') to crawl endpoints")
    if not cdn_or_waf:
        result.recommended.append("No WAF detected — direct testing likely viable")

    return result


# ---------------------------------------------------------------------------
# http_request summarizer
# ---------------------------------------------------------------------------

def _summarize_http_request(raw: str, ctx: dict) -> SummaryResult:
    """Parse HTTP response from http(action='request')."""
    result = SummaryResult()
    url = ctx.get("url", "")
    method = ctx.get("method", "GET")

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        result.summary = f"{method} {url} — raw response (not JSON)"
        result.facts.append(f"Raw length: {len(raw)} chars")
        result.evidence = {"raw_length": len(raw)}
        return result

    if "error" in data:
        result.summary = f"{method} {url} — ERROR: {data['error']}"
        result.anomalies.append(data["error"])
        if "hint" in data:
            result.facts.append(data["hint"])
        result.evidence = {"error": data["error"]}
        return result

    status = data.get("status", 0)
    headers = data.get("headers", {})
    body = data.get("body", "")

    result.summary = f"{method} {url} returned HTTP {status}"

    result.facts.append(f"Status: {status}")
    if headers.get("Content-Type"):
        result.facts.append(f"Content-Type: {headers['Content-Type']}")
    if headers.get("Server"):
        result.facts.append(f"Server: {headers['Server']}")
    result.facts.append(f"Body length: {len(body)} chars")

    # Extract interesting patterns from body
    _extract_body_signals(body, result)

    result.evidence = {
        "status": status,
        "content_type": headers.get("Content-Type", ""),
        "body_preview": body[:500],
    }

    # Security-relevant headers
    security_headers = ["X-Frame-Options", "Content-Security-Policy",
                        "Strict-Transport-Security", "X-Content-Type-Options"]
    missing = [h for h in security_headers if h.lower() not in {k.lower() for k in headers}]
    if missing:
        result.facts.append(f"Missing security headers: {', '.join(missing)}")

    return result


def _extract_body_signals(body: str, result: SummaryResult) -> None:
    """Detect interesting patterns in response body."""
    lower = body.lower()

    if "werkzeug" in lower and "debugger" in lower:
        result.anomalies.append("Werkzeug debugger detected — potential RCE")
    if "traceback" in lower or "stack trace" in lower:
        result.anomalies.append("Stack trace in response — information disclosure")
    if "sql" in lower and ("syntax" in lower or "error" in lower):
        result.anomalies.append("Possible SQL error in response")
    if any(kw in lower for kw in ("password", "secret", "api_key", "apikey", "token")):
        result.anomalies.append("Sensitive keyword detected in response body")


# ---------------------------------------------------------------------------
# kali_sqlmap summarizer
# ---------------------------------------------------------------------------

def _process_sqlmap_line(stripped: str, state: dict) -> bool:
    """Update state with data from one stripped sqlmap output line.

    Returns True when the 'not injectable' signal is found (caller should stop).
    """
    if "all tested parameters do not appear to be injectable" in stripped.lower():
        return True
    m = re.match(r"Parameter:\s+(\S+)\s+\((\w+)\)", stripped)
    if m:
        state["injectable_params"].append(f"{m.group(1)} ({m.group(2)})")
    if "is vulnerable" in stripped.lower():
        state["is_vulnerable"] = True
    m = re.match(r"back-end DBMS:\s+(.+)", stripped, re.I)
    if m:
        state["db_type"] = m.group(1).strip()
    if re.match(r"\[\*\]\s+\w+", stripped):
        db_name = stripped.lstrip("[*] ").strip()
        if db_name and db_name not in state["databases"]:
            state["databases"].append(db_name)
    m = re.match(r"\|\s+(\w+)\s+\|", stripped)
    if m:
        state["tables"].append(m.group(1))
    return False


def _parse_sqlmap_lines(lines: list[str]) -> dict | None:
    """Parse sqlmap output lines. Returns None if 'not injectable' is detected."""
    state: dict = {
        "injectable_params": [], "db_type": "", "databases": [], "tables": [], "is_vulnerable": False,
    }
    for line in lines:
        if _process_sqlmap_line(line.strip(), state):
            return None
    return {
        "injectable_params": state["injectable_params"],
        "db_type": state["db_type"],
        "databases": state["databases"],
        "tables": state["tables"],
        "is_vulnerable": state["is_vulnerable"] or bool(state["injectable_params"]),
    }


def _build_sqlmap_vulnerable_result(result: SummaryResult, parsed: dict) -> None:
    """Populate result fields when sqlmap found injectable parameters."""
    injectable_params = parsed["injectable_params"]
    db_type = parsed["db_type"]
    params_str = ", ".join(injectable_params) if injectable_params else "unknown"
    result.summary = f"SQLi CONFIRMED on parameter(s): {params_str}"
    if db_type:
        result.summary += f" (DBMS: {db_type})"
    result.facts.append(f"Injectable: {params_str}")
    if db_type:
        result.facts.append(f"DBMS: {db_type}")
    if parsed["databases"]:
        result.facts.append(f"Databases: {', '.join(parsed['databases'][:10])}")
    if parsed["tables"]:
        result.facts.append(f"Tables: {', '.join(parsed['tables'][:20])}")
    result.recommended.append("Dump credentials: kali(command='sqlmap ... --dump -T users')")
    result.recommended.append("Try OS shell: kali(command='sqlmap ... --os-shell')")


def _summarize_kali_sqlmap(raw: str, ctx: dict) -> SummaryResult:
    """Parse sqlmap output for injection results."""
    result = SummaryResult()
    lines = raw.strip().splitlines()

    parsed = _parse_sqlmap_lines(lines)
    if parsed is None:
        result.summary = "sqlmap: no injection found"
        result.facts.append("All tested parameters not injectable")
        return result

    if parsed["is_vulnerable"]:
        _build_sqlmap_vulnerable_result(result, parsed)
    else:
        result.summary = "sqlmap scan completed — check artifact for details"

    result.evidence = {
        "injectable_params": parsed["injectable_params"],
        "dbms": parsed["db_type"],
        "databases": parsed["databases"][:10],
        "tables": parsed["tables"][:20],
        "vulnerable": parsed["is_vulnerable"],
    }

    return result


# ---------------------------------------------------------------------------
# naabu summarizer
# ---------------------------------------------------------------------------

def _summarize_naabu(raw: str, ctx: dict) -> SummaryResult:
    """Parse naabu JSON lines output for open ports."""
    result = SummaryResult()
    ports: dict[str, set[int]] = {}  # host -> set of ports

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "?")
            port = data.get("port")
            if port:
                ports.setdefault(host, set()).add(int(port))
        except ValueError:
            continue

    if ports:
        all_ports = sorted(set().union(*ports.values()))
        result.summary = f"Found {len(all_ports)} open port(s): {', '.join(str(p) for p in all_ports)}"
        for host, host_ports in ports.items():
            result.facts.append(f"{host}: {', '.join(str(p) for p in sorted(host_ports))}")
        result.evidence = {"ports": all_ports, "hosts": list(ports.keys())}
    else:
        result.summary = "naabu: no open ports found"
        result.evidence = {"ports": [], "hosts": []}

    return result


# ---------------------------------------------------------------------------
# subfinder summarizer
# ---------------------------------------------------------------------------

def _summarize_subfinder(raw: str, ctx: dict) -> SummaryResult:
    """Parse subfinder output — one subdomain per line."""
    result = SummaryResult()
    subs = [l.strip() for l in raw.strip().splitlines() if l.strip() and not l.startswith("[")]

    if subs:
        result.summary = f"Found {len(subs)} subdomain(s)"
        result.facts = subs[:20]
        if len(subs) > 20:
            result.facts.append(f"... and {len(subs) - 20} more")
        result.evidence = {"subdomains": subs[:50], "count": len(subs)}
    else:
        result.summary = "subfinder: no subdomains found"
        result.evidence = {"subdomains": [], "count": 0}

    return result


# ---------------------------------------------------------------------------
# nuclei summarizer
# ---------------------------------------------------------------------------

def _parse_nuclei_line(line: str) -> dict | None:
    """Parse a single nuclei output line (JSON or text). Returns a finding dict or None."""
    if line.startswith("{"):
        try:
            data = json.loads(line)
            return {
                "template": data.get("template-id", data.get("templateID", "?")),
                "severity": data.get("info", {}).get("severity", "?"),
                "name": data.get("info", {}).get("name", "?"),
                "matched": data.get("matched-at", data.get("matched", "?")),
            }
        except json.JSONDecodeError:
            return None
    m = re.match(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)', line)
    if m:
        return {
            "template": m.group(1),
            "severity": m.group(2),
            "name": m.group(1),
            "matched": m.group(4).strip(),
        }
    return None


def _summarize_nuclei(raw: str, ctx: dict) -> SummaryResult:
    """Parse nuclei output for vulnerability findings."""
    result = SummaryResult()
    findings: list[dict] = []

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        finding = _parse_nuclei_line(line)
        if finding:
            findings.append(finding)

    if findings:
        crit_high = [f for f in findings if f["severity"] in ("critical", "high")]
        result.summary = f"nuclei found {len(findings)} issue(s)"
        if crit_high:
            result.summary += f" ({len(crit_high)} critical/high)"
        for f in findings[:20]:
            result.facts.append(f"[{f['severity']}] {f['template']}: {f['matched']}")
        result.evidence = {"findings": findings[:30], "total": len(findings)}
    else:
        result.summary = "nuclei: no vulnerabilities found"
        result.evidence = {"findings": [], "total": 0}

    return result


# ---------------------------------------------------------------------------
# ffuf summarizer
# ---------------------------------------------------------------------------

def _parse_ffuf_json(raw: str) -> list[dict] | None:
    """Parse ffuf JSON output (-of json). Returns list of path dicts or None on parse error."""
    try:
        data = json.loads(raw)
        return [
            {"url": r.get("url", "?"), "status": r.get("status", 0), "length": r.get("length", 0)}
            for r in data.get("results", [])
        ]
    except (json.JSONDecodeError, TypeError):
        return None


def _parse_ffuf_text(raw: str) -> list[dict]:
    """Parse ffuf text output. Returns list of path dicts."""
    paths: list[dict] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        m = re.match(r'(\d{3})\s+\S+\s+\S+\s+(.*)', line)
        if m:
            paths.append({"url": m.group(2).strip(), "status": int(m.group(1)), "length": 0})
        elif line.startswith("http"):
            paths.append({"url": line, "status": 0, "length": 0})
    return paths


def _summarize_ffuf(raw: str, ctx: dict) -> SummaryResult:
    """Parse ffuf output for discovered paths."""
    result = SummaryResult()
    paths = _parse_ffuf_json(raw)
    if paths is None:
        paths = _parse_ffuf_text(raw)

    if paths:
        result.summary = f"ffuf found {len(paths)} path(s)"
        for p in paths[:25]:
            status_str = f" [{p['status']}]" if p["status"] else ""
            result.facts.append(f"{p['url']}{status_str}")
        result.evidence = {"paths": paths[:50], "total": len(paths)}
    else:
        result.summary = "ffuf: no paths discovered"
        result.evidence = {"paths": [], "total": 0}

    return result


# ---------------------------------------------------------------------------
# spider summarizer
# ---------------------------------------------------------------------------

_STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
}


def _extract_url_params(parsed_url: Any) -> list[dict]:
    """Extract query and path parameters from a parsed URL object."""
    from urllib.parse import parse_qs
    params: list[dict] = []
    path = parsed_url.path
    for name in parse_qs(parsed_url.query):
        if not name.startswith("__"):
            params.append({"name": name, "type": "query", "value_hint": "string"})
    for i, seg in enumerate(path.split("/")):
        if seg.isdigit():
            params.append({"name": f"id_{i}", "type": "path", "value_hint": "integer"})
    return params


def _extract_dynamic_endpoints(urls: list[str]) -> list[dict]:
    """Filter static assets and deduplicate URL paths into unique dynamic endpoints."""
    from urllib.parse import urlparse
    seen_paths: set[str] = set()
    endpoints: list[dict] = []
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.split("/")[-1] else ""
        if ext in _STATIC_EXTENSIONS:
            continue
        norm = re.sub(r'/\d+', '/{id}', path)
        if norm in seen_paths:
            continue
        seen_paths.add(norm)
        endpoints.append({"path": norm, "method": "GET", "params": _extract_url_params(parsed)})
    return endpoints


def _summarize_spider(raw: str, ctx: dict) -> SummaryResult:
    """Parse katana/spider output — one URL per line. Extract endpoints for registration."""
    result = SummaryResult()
    urls = [l.strip() for l in raw.strip().splitlines() if l.strip() and l.strip().startswith("http")]

    if not urls:
        result.summary = "Spider: no URLs discovered"
        result.evidence = {"urls": [], "count": 0}
        return result

    endpoints = _extract_dynamic_endpoints(urls)

    result.summary = f"Spider crawled {len(urls)} URL(s), {len(endpoints)} unique endpoint(s)"
    result.facts = [f"{ep['path']}" + (f" params={[p['name'] for p in ep['params']]}" if ep['params'] else "") for ep in endpoints[:20]]
    result.evidence = {"endpoints": endpoints[:30], "all_urls_count": len(urls)}

    for ep in endpoints[:10]:
        params_json = json.dumps(ep["params"]) if ep["params"] else "[]"
        result.required.append(
            f"report(action='coverage', data={{\"type\":\"endpoint\", \"path\":\"{ep['path']}\", "
            f"\"method\":\"{ep['method']}\", \"params\":{params_json}, \"discovered_by\":\"spider\"}})"
        )

    return result


# ---------------------------------------------------------------------------
# Generic fallback summarizer
# ---------------------------------------------------------------------------

def _summarize_generic(raw: str, ctx: dict) -> SummaryResult:
    """Fallback: first 5 lines + line count."""
    result = SummaryResult()
    lines = raw.strip().splitlines()
    tool = ctx.get("_tool", "tool")

    result.summary = f"{tool} returned {len(lines)} line(s) of output"
    result.facts = [l.strip()[:300] for l in lines[:5] if l.strip()]
    if len(lines) > 5:
        result.facts.append(f"... and {len(lines) - 5} more line(s)")
    result.evidence = {"total_lines": len(lines), "total_chars": len(raw)}

    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_SUMMARIZERS: dict[str, Any] = {
    "httpx": _summarize_httpx,
    "http_request": _summarize_http_request,
    "kali_sqlmap": _summarize_kali_sqlmap,
    "naabu": _summarize_naabu,
    "nmap": _summarize_naabu,  # similar JSON lines format
    "subfinder": _summarize_subfinder,
    "nuclei": _summarize_nuclei,
    "ffuf": _summarize_ffuf,
    "spider": _summarize_spider,
}
