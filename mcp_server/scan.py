"""
Scan session management
=======================
start_scan, complete_scan, and log_note — session lifecycle and guardrails.
"""
import os

from core import cost as cost_tracker
from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp, _session_tools_called


@mcp.tool()
async def start_scan(
    target:           str,
    depth:            str        = "standard",
    scope:            list[str]  | None = None,
    out_of_scope:     list[str]  | None = None,
    max_cost_usd:     float | None = None,
    max_time_minutes: int   | None = None,
    max_tool_calls:   int   | None = None,
) -> str:
    """
    Initialise a scan session with defined scope and hard limits.
    ALWAYS call this before any other tool — it sets the guardrails that
    prevent the scan from running forever or exceeding the budget.

    depth presets (override any limit with the explicit params):
      recon    — port scan + subdomains + HTTP probe only     ($0.10 / 15 min / 10 calls)
      standard — recon + nuclei + dir fuzzing                 ($0.50 / 45 min / 25 calls)
      thorough — standard + full Kali toolchain               ($2.00 / 120 min / 60 calls)

    scope        : list of in-scope hosts/domains (defaults to [target])
    out_of_scope : explicit exclusions Claude must not touch
    """
    _session_tools_called.clear()
    cfg = scan_session.start(
        target=target, depth=depth,
        scope=scope, out_of_scope=out_of_scope,
        max_cost_usd=max_cost_usd,
        max_time_minutes=max_time_minutes,
        max_tool_calls=max_tool_calls,
    )
    log.note(
        f"Scan started — target={target}  depth={depth}  "
        f"limits: ${cfg['limits']['max_cost_usd']} / "
        f"{cfg['limits']['max_time_minutes']}min / "
        f"{cfg['limits']['max_tool_calls']} calls"
    )
    lim = cfg["limits"]
    lines = [
        f"Scan session started.",
        f"  Target      : {target}",
        f"  Depth       : {cfg['depth_label']} — {cfg['description']}",
        f"  Scope       : {', '.join(cfg['scope'])}",
    ]
    if cfg["out_of_scope"]:
        lines.append(f"  Out-of-scope: {', '.join(cfg['out_of_scope'])}")
    lines += [
        f"  Cost limit  : ${lim['max_cost_usd']}",
        f"  Time limit  : {lim['max_time_minutes']} min",
        f"  Call limit  : {lim['max_tool_calls']} tool calls",
        f"",
        f"Proceed with the {depth} scan workflow.",
        f"Stop and call complete_scan() when finished or when a limit is hit.",
    ]
    return "\n".join(lines)


@mcp.tool()
async def complete_scan(notes: str = "") -> str:
    """
    Mark the scan as complete. Call this when:
      - all planned tools have run, OR
      - a limit was hit and you have written the final report.
    notes : brief summary of what was found / why stopping.

    BLOCKED until:
      1. At least one report_diagram has been called (application/network diagram).
      2. Every high or critical finding has a matching PoC saved via save_poc.
    """
    blockers: list[str] = []

    data = findings_store._load()

    # ── Check 1: diagram required ─────────────────────────────────────────────
    if not data.get("diagrams"):
        blockers.append(
            "NO DIAGRAM: call report_diagram() with a Mermaid diagram of the application "
            "architecture (components, endpoints, and features tested) before completing."
        )

    # ── Check 2: spider required when web targets were probed ────────────────
    if "httpx" in _session_tools_called and "spider" not in _session_tools_called:
        blockers.append(
            "NO SPIDER: run_httpx confirmed web targets but run_spider was never called. "
            "Run run_spider(url, mode='fast') to crawl the application before completing."
        )

    # ── Check 3: PoC required for every high/critical finding ────────────────
    repo_root = os.path.dirname(os.path.dirname(__file__))
    pocs_dir  = os.path.join(repo_root, "pocs")
    poc_files = set(os.listdir(pocs_dir)) if os.path.isdir(pocs_dir) else set()
    high_findings = [
        f for f in data.get("findings", [])
        if f.get("severity") in ("high", "critical")
    ]
    if high_findings and not poc_files:
        titles = ", ".join(f["title"] for f in high_findings)
        blockers.append(
            f"NO POC FILES: {len(high_findings)} high/critical finding(s) have no Burp PoC. "
            f"Call http_request(poc=True) + save_poc() for each: {titles}"
        )

    if blockers:
        msg = "complete_scan BLOCKED — fix the following before calling complete_scan again:\n\n"
        msg += "\n\n".join(f"  [{i+1}] {b}" for i, b in enumerate(blockers))
        log.note(f"complete_scan blocked: {'; '.join(blockers)}")
        return msg

    cfg    = scan_session.complete(notes)
    status = cfg.get("status", "complete")
    log.note(f"Scan complete — {notes}")
    return f"Scan marked {status}. session.json updated."


@mcp.tool()
async def log_note(message: str) -> str:
    """
    Write a reasoning note, decision, or observation to the session log.
    Use this to record why you chose a particular tool or approach,
    what you noticed, or what you plan to do next.
    """
    log.note(message)
    return "Logged."
