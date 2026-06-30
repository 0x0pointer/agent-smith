"""
QA agent — scan-health checks that escalate to HIR.

Conditions Smith cannot self-resolve: expired auth, exhausted budget with low
coverage, an empty matrix after a 0-endpoint spider, an unreachable target,
and repeated same-tool failures. Each pauses the scan via ``_hir``. The lone
exception is ``_check_exploit_escalation`` — benchmark-mode only, which pushes
exploitation via a steering directive instead of pausing.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.qa_agent as _qa
from ._util import _ts_age_secs
from .hir import _hir

# Tools that run in-process (Python aiohttp / requests / playwright) and
# therefore have NO Docker dependency. Failure modes here are network /
# target / DNS / SSL, not container infrastructure.
_PYTHON_NATIVE_TOOLS = {"http_request", "spider"}
_ABORT_OPTION = "ABORT: Stop the scan"


def _reauth_hint(session_data: dict | None) -> str:
    """Concrete re-auth instruction from whatever auth assets Smith already holds."""
    ka = (session_data or {}).get("known_assets", {}) or {}
    creds = ka.get("credentials") or []
    auth_eps = ka.get("auth_endpoints") or []
    ep = ""
    if auth_eps:
        first = auth_eps[0]
        ep = (first.get("path") or first.get("url") or "") if isinstance(first, dict) else str(first)
    if ep and creds:
        return f"POST known_assets.credentials to the login endpoint (known_assets.auth_endpoints, e.g. {ep})."
    if ep:
        return f"Re-login at a known auth endpoint (known_assets.auth_endpoints, e.g. {ep})."
    if creds:
        return "Re-login with known_assets.credentials at the app's login endpoint."
    return ("Re-run whatever produced your token before — re-login, an auth bypass "
            "(e.g. SQLi on /login), or registering a fresh user.")


def _check_auth_failure(entries: list[dict], session_data: dict, previous_alerts: list[dict]) -> dict | None:
    """Recover expired session auth mid-scan — self-heal first, HIR only if that fails.

    Fires when >60% of the last 10 non-auth http_request calls return 401/403 AND
    there were earlier 2xx calls (auth worked before). On the FIRST detection it
    steers Smith to re-authenticate itself (it usually holds creds / a login
    bypass) and returns a non-blocking AUTH_REAUTH advisory — no human pause. Only
    if a prior cycle already issued that steer and 401/403 still dominates does it
    escalate to HIR_AUTH_FAILURE.
    """
    http_entries = [
        e for e in entries
        if e.get("type") == "TOOL" and e.get("name") == "http_request"
        and e.get("status_code")
    ]
    if len(http_entries) < 5:
        return None
    # Check if auth ever worked (any 2xx in history)
    ever_authed = any(200 <= e.get("status_code", 0) < 300 for e in http_entries)
    if not ever_authed:
        return None
    # Exclude credential-validation attempts (entries flagged as auth_attempt
    # by the envelope — request body contained password/secret/api_key/etc.,
    # or URL matched a known auth endpoint). 401s on those are credential
    # tests, not session expiry — counting them here causes false-positive HIRs
    # while Smith is actively logging in.
    recent = http_entries[-10:]
    non_auth_recent = [e for e in recent if not e.get("auth_attempt")]
    if len(non_auth_recent) < 5:
        return None  # too few non-auth signals to judge session validity
    auth_failures = [e for e in non_auth_recent if e.get("status_code") in (401, 403)]
    if len(auth_failures) / len(non_auth_recent) < 0.6:
        return None
    # Rebind `recent` for the message below so target/counts reflect the
    # signal we actually triggered on, not credential-attempt noise.
    recent = non_auth_recent
    target = recent[-1].get("target", "target")
    ratio = f"{len(auth_failures)}/{len(recent)}"

    # Self-heal first: on the FIRST detection, steer Smith to re-authenticate
    # itself instead of pausing for a human. Escalate to HIR only once that steer
    # was already issued and 401/403 still dominates — i.e. auto-reauth failed.
    already_steered = any(a.get("code") == "AUTH_REAUTH" for a in (previous_alerts or []))
    if not already_steered:
        if not _qa._has_pending_directives():
            from core.steering import RESUME_TESTING, steering_queue
            steering_queue.add_directive(
                code=RESUME_TESTING,
                message=(
                    f"SESSION EXPIRED — {ratio} recent requests to {target} returned 401/403 after "
                    "auth worked earlier. RE-AUTHENTICATE YOURSELF; do NOT wait for a human. "
                    + _reauth_hint(session_data)
                    + " Capture the fresh 'Authorization: Bearer <token>' and retry the failed "
                    "requests with it — this only escalates to a human if re-auth genuinely fails."
                ),
                priority="high", skill=None, trigger="AUTH_REAUTH",
            )
        return {
            "code": "AUTH_REAUTH", "urgency": "high", "blocking": False,
            "message": (
                f"Session likely expired ({ratio} 401/403 on {target}) — "
                "re-authenticate and retry before escalating to a human"
            ),
        }

    # Auto-reauth was already attempted and 401/403 still dominates → human.
    _hir(
        code="HIR_AUTH_FAILURE",
        situation=(
            f"{ratio} recent HTTP requests to {target} returned 401/403 after previously "
            "authenticated calls succeeded, and an automatic re-authentication attempt did not "
            "recover the session. Credentials appear expired/locked, or there is no usable login."
        ),
        tried=[
            f"{len(auth_failures)} consecutive auth failures (401/403)",
            "auto re-authentication was steered, but 401/403 persists",
        ],
        options=[
            "RECREDENTIAL: Provide fresh session cookies or API tokens — I will inject them and resume",
            "REAUTH: Tell me the login endpoint and credentials — I will re-authenticate",
            "SKIP_AUTH: Continue with unauthenticated testing only and document the coverage gap",
            "ABORT: Stop the scan — auth cannot be recovered",
        ],
    )
    return {
        "code": "HIR_AUTH_FAILURE", "urgency": "high", "blocking": False,
        "message": f"Auth still failing after auto-reauth: {ratio} recent requests 401/403 — needs human",
    }


def _check_budget_limit(session_data: dict, coverage_data: dict) -> dict | None:
    """HIR when tool call budget is >90% used but scan coverage is <80% complete."""
    calls_used = session_data.get("calls_used", 0)
    max_calls  = session_data.get("max_tool_calls", 0)
    if not max_calls or calls_used / max_calls < 0.9:
        return None
    meta = coverage_data.get("meta", {})
    total = meta.get("total_cells", 0)
    tested = meta.get("tested", 0) + meta.get("not_applicable", 0)
    coverage_pct = (tested / total) if total else 1.0
    if coverage_pct >= 0.8:
        return None  # Nearly done — let Smith finish
    remaining_calls = max_calls - calls_used
    pending_cells = total - tested
    _hir(
        code="HIR_BUDGET_LIMIT",
        situation=(
            f"{calls_used}/{max_calls} tool calls used ({int(calls_used/max_calls*100)}%) "
            f"but only {int(coverage_pct*100)}% of coverage complete "
            f"({pending_cells} cells pending, ~{remaining_calls} calls left). "
            "The scan cannot complete all planned testing within the current budget."
        ),
        tried=[f"{calls_used} tool calls consumed"],
        options=[
            "EXTEND: Increase max_tool_calls — specify new limit and I will continue",
            "PRIORITIZE: Tell me which endpoint types or findings to focus on — I will test those and skip the rest",
            "ACCEPT_PARTIAL: Complete now with documented coverage gaps in the report",
            "ABORT: Stop the scan immediately",
        ],
    )
    return {
        "code": "HIR_BUDGET_LIMIT", "urgency": "high", "blocking": False,
        "message": f"Budget at {int(calls_used/max_calls*100)}% with {int(coverage_pct*100)}% coverage done — {pending_cells} cells will be missed",
    }


def _check_zero_endpoints(entries: list[dict], coverage_data: dict) -> dict | None:
    """HIR when spider completed but found nothing and coverage matrix is still empty."""
    spider_entries = [e for e in entries if e.get("type") == "SPIDER"]
    if not spider_entries:
        return None
    last_spider = spider_entries[-1]
    if last_spider.get("endpoints_found", 1) > 0:
        return None
    if coverage_data.get("meta", {}).get("total_cells", 0) > 0:
        return None
    # Give Smith 10 min to register endpoints manually before firing
    now = datetime.now(timezone.utc)
    if _ts_age_secs(last_spider.get("ts", ""), now) < 600:
        return None
    target = last_spider.get("target", "target")
    _hir(
        code="HIR_NO_ENDPOINTS",
        situation=(
            f"Spider completed against {target} but found 0 endpoints, "
            "and the coverage matrix is still empty after 10 minutes. "
            "There is nothing to test — the application may require authentication, "
            "a specific entry point, or a different crawl mode."
        ),
        tried=["Spider completed with 0 endpoints discovered"],
        options=[
            "SEED_URLS: Provide specific URLs or API paths to test — I will register them manually and start testing",
            "AUTH_CRAWL: Provide session cookies or auth headers — I will re-spider with authentication",
            "PLAYWRIGHT: Switch to Playwright spider mode for JavaScript-heavy SPAs",
            "ABORT: Target is not crawlable — stop the scan",
        ],
    )
    return {
        "code": "HIR_NO_ENDPOINTS", "urgency": "high", "blocking": False,
        "message": f"Spider found 0 endpoints on {target} and coverage matrix is empty — cannot proceed without human input",
    }


def _check_target_unreachable(entries: list[dict]) -> dict | None:
    """HIR when 3+ consecutive tool calls to the same target all errored out."""
    tool_entries = [e for e in entries if e.get("type") == "TOOL"]
    if len(tool_entries) < 3:
        return None
    # Check last 5 entries for a run of errors on the same target
    recent = tool_entries[-5:]
    # Find longest consecutive error run
    run_target = None
    run_count = 0
    current_target = None
    current_count = 0
    for e in recent:
        t = e.get("target", "")
        if e.get("error") and t == current_target:
            current_count += 1
        elif e.get("error"):
            current_target = t
            current_count = 1
        else:
            current_target = None
            current_count = 0
        if current_count >= run_count:
            run_count = current_count
            run_target = current_target
    if run_count < 3 or not run_target:
        return None
    _hir(
        code="HIR_TARGET_UNREACHABLE",
        situation=(
            f"{run_count} consecutive tool calls to '{run_target}' all failed with errors. "
            "The target may be down, rate-limiting, or blocking scanner traffic."
        ),
        tried=[f"{run_count} consecutive failed tool calls to {run_target}"],
        options=[
            "WAIT: Target may be temporarily down — tell me how long to wait before retrying",
            "ROTATE: Provide an alternative IP, proxy, or User-Agent to bypass the block",
            "SKIP_TARGET: Mark this target as unreachable and continue with remaining scope",
            _ABORT_OPTION,
        ],
    )
    return {
        "code": "HIR_TARGET_UNREACHABLE", "urgency": "high", "blocking": False,
        "message": f"{run_count} consecutive errors against '{run_target}' — target may be down or blocking",
    }


def _check_exploit_escalation(entries: list[dict], findings_data: dict, session_data: dict) -> dict | None:
    """Benchmark mode only: push Smith to exploit critical/high findings deeper.

    In pentest mode this is a human decision (HIR). In benchmark mode, Smith should
    demonstrate full impact autonomously — this directive pushes it to do so instead of
    logging and moving on.

    Fires when a critical/high finding was logged >10 min ago with no exploitation
    tool (metasploit, kali, sqlmap) run against the same target since.
    """
    if session_data.get("scan_mode") != "benchmark":
        return None
    findings = [
        f for f in findings_data.get("findings", [])
        if f.get("severity") in ("critical", "high")
    ]
    if not findings:
        return None
    now = datetime.now(timezone.utc)
    _EXPLOIT_TOOLS = {"metasploit", "kali", "sqlmap", "kali_sqlmap"}
    for finding in findings:
        age_secs = _ts_age_secs(finding.get("ts", ""), now)
        if age_secs < 600:  # 10 min grace
            continue
        target = finding.get("target", "")
        exploit_tools_after = [
            e for e in entries
            if e.get("type") == "TOOL"
            and e.get("name", "") in _EXPLOIT_TOOLS
            and e.get("target", "") == target
            and e.get("ts", "") > finding.get("ts", "")
        ]
        if exploit_tools_after:
            continue
        age_mins = int(age_secs / 60)
        if not _qa._has_pending_directives():
            from core.steering import steering_queue, RESUME_TESTING
            steering_queue.add_directive(
                code=RESUME_TESTING,
                message=(
                    f"[BENCHMARK] You found '{finding['title']}' ({finding['severity']}) "
                    f"{age_mins}min ago — demonstrate full impact. "
                    "Do NOT stop at the finding. Chain exploitation: "
                    "try privilege escalation, data extraction, lateral movement, or persistence. "
                    "Use kali(), metasploit, or sqlmap to prove the real-world impact. "
                    "Document every step as a finding before moving on."
                ),
                priority="high", skill=None, trigger="EXPLOIT_ESCALATION",
            )
        return {
            "code": "EXPLOIT_ESCALATION", "urgency": "high", "blocking": False,
            "message": f"[BENCHMARK] '{finding['title']}' found {age_mins}min ago — no exploitation follow-up yet",
        }
    return None


def _check_repeated_tool_failure(entries: list[dict]) -> dict | None:
    """HIR when the same tool fails 3+ times in a row — likely an infrastructure issue.

    Message + remediation options are tool-aware: Python-native tools
    (http_request, spider) get a target-reachability framing; Docker-backed
    tools (kali, metasploit, nuclei, ...) keep the container/infra framing.
    """
    tool_entries = [e for e in entries if e.get("type") == "TOOL" and e.get("error")]
    if len(tool_entries) < 3:
        return None
    # Check if the last 3 error entries are from the same tool
    last_three = tool_entries[-3:]
    tools_in_run = {e.get("name") for e in last_three}
    if len(tools_in_run) != 1:
        return None  # Different tools failing — not an infra issue for one specific tool
    broken_tool = last_three[0].get("name", "unknown")
    # Only fire if all 3 are recent (last 20 min)
    now = datetime.now(timezone.utc)
    if any(_ts_age_secs(e.get("ts", ""), now) > 1200 for e in last_three):
        return None

    is_python_native = broken_tool in _PYTHON_NATIVE_TOOLS
    if is_python_native:
        situation = (
            f"Tool '{broken_tool}' has failed 3 times in a row in the last 20 minutes. "
            f"'{broken_tool}' runs in-process (Python aiohttp/requests) and has no "
            "container dependency — most likely a target reachability problem: target "
            "down, DNS failure, SSL/TLS error, or proxy/network block."
        )
        options = [
            "WAIT: Target may be temporarily down — tell me how long to wait before retrying",
            "VERIFY: Confirm the target URL is correct (DNS, port, scheme) and I will retry",
            "ROTATE: Provide an alternative proxy / User-Agent / endpoint to bypass blocks",
            "SKIP_TOOL: Stop using this tool and rely on alternatives for the rest of the scan",
            _ABORT_OPTION,
        ]
        message = (
            f"Tool '{broken_tool}' failed 3 times in a row — target reachability / network suspected"
        )
    else:
        situation = (
            f"Tool '{broken_tool}' has failed 3 times in a row in the last 20 minutes. "
            "This is likely a Docker/infrastructure issue rather than a target problem."
        )
        options = [
            "RESTART_INFRA: I will run session(action='start_kali') to restart the Kali container and retry",
            "SKIP_TOOL: Tell me to avoid this tool for the rest of the scan and use alternatives",
            "INVESTIGATE: Check the logs — run `docker ps` to verify containers are healthy",
            _ABORT_OPTION,
        ]
        message = (
            f"Tool '{broken_tool}' failed 3 times in a row — infrastructure issue suspected"
        )

    _hir(
        code="HIR_TOOL_FAILURE",
        situation=situation,
        tried=[f"'{broken_tool}' called 3 times, all failed with errors"],
        options=options,
    )
    return {
        "code": "HIR_TOOL_FAILURE", "urgency": "high", "blocking": False,
        "message": message,
    }
