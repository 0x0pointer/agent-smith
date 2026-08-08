"""Network / recon summarizers — naabu (also nmap), subfinder, nuclei."""
from __future__ import annotations

import json
import re

from ._common import SummaryResult


# ---------------------------------------------------------------------------
# naabu summarizer
# ---------------------------------------------------------------------------

def _summarize_naabu(raw: str, _ctx: dict) -> SummaryResult:
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

def _summarize_subfinder(raw: str, _ctx: dict) -> SummaryResult:
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


def _summarize_nuclei(raw: str, _ctx: dict) -> SummaryResult:
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
