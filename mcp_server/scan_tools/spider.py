"""Spider handler: fast/playwright/deep modes + thorough (katana+playwright+ZAP Client Spider).

`deep` mode and the `thorough` merge use the ZAP **Client Spider** (ZAP 2.16+) via the
official ZAP image (tools/zap_runner.py), replacing the discontinued zap-cli AJAX spider
(issue #184). It crawls black-box, then authenticated when a session is available."""
import shlex

from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import _clip, _record
from ._common import _spider_succeeded


async def _run_spider_thorough(target: str, flags: str, cookies: dict, depth: str, max_pages: str, budget_s: int) -> str:
    """Run katana + playwright + ZAP AJAX spider in thorough mode and return merged raw output."""
    import asyncio as _asyncio
    from tools import kali_runner
    import json as _json

    safe_url = shlex.quote(target)
    safe_cookies = shlex.quote(_json.dumps(cookies))
    # Split the budget across the 3 subtools so total wall-clock caps at the
    # user-provided `budget_s` value (default 2h → ~40min per subtool, floor
    # 20min so a tiny budget doesn't starve any one tool).
    per_subtool = max(budget_s // 3, 1200)
    log.note(f"spider: thorough mode — katana + playwright + zap-client-spider (per-subtool timeout={per_subtool}s)")

    safe_flags = shlex.join(shlex.split(flags)) if flags else ""
    rate_flag = "" if "-rate-limit" in (flags or "") else "-rate-limit 50"
    katana_cmd = f"katana -u {safe_url} -d {depth} -silent -no-color {rate_flag}".strip()
    if safe_flags:
        katana_cmd += f" {safe_flags}"

    playwright_cmd = (
        f"playwright-spider --url {safe_url} --cookies {safe_cookies} "
        f"--depth {depth} --max-pages {max_pages}"
    )

    parts = []
    for label, cmd, t in [
        ("=== katana ===", katana_cmd, per_subtool),
        ("=== playwright ===", playwright_cmd, per_subtool),
    ]:
        async with _asyncio.timeout(t):
            # SP-11: keep the FULL sub-tool output — discovery parses every URL
            # from it. The inline summary/cost are bounded downstream in
            # _handle_spider; clipping here silently dropped the deep-crawl tail
            # (the interesting admin/API routes) before cells were ever generated.
            out = await kali_runner.exec_command(cmd)
        parts.append(f"{label}\n{out}")

    # ZAP Client Spider (issue #184) — official image, not Kali/zap-cli. DOM-aware
    # discovery, two-pass (black-box + authenticated). Runs its own container, so it's
    # outside the kali exec loop above.
    zap_out = await _run_zap_client_spider(target, per_subtool, cookies)
    parts.append(f"=== zap-client-spider ===\n{zap_out}")

    return "\n\n".join(parts)


async def _run_spider_fast(target: str, flags: str, cookies: dict, depth: str, max_pages: str, mode: str, budget_s: int) -> str:
    """Run the fast/playwright/deep spider mode and return raw output."""
    import asyncio as _asyncio
    from tools import kali_runner
    import json as _json

    safe_url = shlex.quote(target)
    safe_cookies = shlex.quote(_json.dumps(cookies))

    if mode == "deep":
        # deep = the ZAP Client Spider (issue #184), its own official-image container.
        return await _run_zap_client_spider(target, budget_s, cookies)

    if mode == "playwright":
        cmd = (
            f"playwright-spider --url {safe_url} --cookies {safe_cookies} "
            f"--depth {depth} --max-pages {max_pages}"
        )
    else:
        safe_flags = shlex.join(shlex.split(flags)) if flags else ""
        rate_flag = "" if "-rate-limit" in (flags or "") else "-rate-limit 50"
        cmd = f"katana -u {safe_url} -d {depth} -silent -no-color {rate_flag}".strip()
        if safe_flags:
            cmd += f" {safe_flags}"

    async with _asyncio.timeout(budget_s):
        # SP-11: return the FULL crawl; bounding happens in _handle_spider.
        return await kali_runner.exec_command(cmd)


def _authpass_deferral_note(target: str) -> str:
    """When the authenticated ZAP pass can't run (no session yet), either tell the
    agent to log in with auth it already holds, or file a credentials wishlist so the
    operator can supply a session — then a later spider run does the authenticated pass.
    Mirrors the wishlist anti-moral-hazard rule: don't ask for creds you can mint yourself."""
    ka = (scan_session.get() or {}).get("known_assets") or {}
    if ka.get("credentials") or ka.get("auth_tokens") or ka.get("auth_endpoints"):
        return ("[zap client-spider: black-box pass only — no active session yet. You already "
                "hold credentials / a login endpoint: authenticate (mint a session), then re-run "
                "the spider so the authenticated Client Spider pass crawls behind the login.]")
    try:
        from core.wishlist import wishlist_queue
        wishlist_queue.add(
            need=(f"an authenticated session (cookies or bearer token) for {target} — the ZAP "
                  "Client Spider finds the real app behind the login; the black-box pass only "
                  "reached the public surface"),
            category="credentials",
            rationale=("Two-pass discovery (issue #184): the black-box Client Spider pass is done; "
                       "the authenticated pass needs a logged-in session to reach auth-gated "
                       "DOM/endpoints."),
        )
        log.note(f"zap client-spider: filed credentials wishlist for authenticated pass on {target}")
    except Exception as exc:  # pragma: no cover - defensive
        log.note(f"zap client-spider: wishlist add skipped: {exc}")
    return ("[zap client-spider: black-box pass only — no session and no credentials known. "
            "Filed a credentials wishlist; once the operator supplies a session, re-run the "
            "spider for the authenticated pass.]")


async def _run_zap_client_spider(target: str, total_seconds: int, cookies: dict) -> str:
    """ZAP Client Spider discovery (issue #184) — the official-image replacement for the
    discontinued zap-cli AJAX spider. Runs a black-box pass always, then an AUTHENTICATED
    pass when a session is available (session injected into every request via a ZAP
    Replacer rule), else files a credentials wishlist. Returns merged discovered-URL lines
    (+ notes) so the normal auto-discovery parses them. Fail-soft — never raises."""
    from tools import zap_runner
    try:
        auth = _spider_discovery_auth(cookies)
        passes = 2 if auth else 1
        # Split the budget across the pass(es); bound each spider's -m to a sane range.
        minutes = max(2, min(20, (total_seconds // 60) // passes))
        per_pass_timeout = minutes * 60 + 180      # + ZAP/Firefox startup headroom
        lines: list[str] = []

        bb = await zap_runner.run_client_spider(target, minutes=minutes, auth=None,
                                                timeout=per_pass_timeout)
        lines.append(bb["note"])
        lines.extend(bb["urls"])

        if auth:
            ap = await zap_runner.run_client_spider(target, minutes=minutes, auth=auth,
                                                    timeout=per_pass_timeout)
            lines.append(ap["note"])
            lines.extend(ap["urls"])
        else:
            lines.append(_authpass_deferral_note(target))
        return "\n".join(lines)
    except Exception as exc:  # pragma: no cover - defensive
        log.note(f"zap client-spider skipped: {exc}")
        return f"[zap client-spider skipped: {exc}]"


def _crawl_cookie_map(crawl_cookies: dict | None) -> dict:
    """Stringified name→value map from the crawl's cookies, or {} when absent."""
    if not isinstance(crawl_cookies, dict):
        return {}
    return {str(k): str(v) for k, v in crawl_cookies.items()}


def _bearer_headers(known_assets: dict) -> dict:
    """``{"Authorization": "Bearer <latest token>"}`` from known_assets, or {} when none."""
    toks = known_assets.get("auth_tokens") or []
    if not toks:
        return {}
    last = toks[-1]
    val = last.get("value") if isinstance(last, dict) else last
    return {"Authorization": f"Bearer {val}"} if val else {}


def _session_cookie_map(known_assets: dict) -> dict:
    """Captured session cookies from known_assets as a name→value map (CH-2 populates this)."""
    out: dict = {}
    for c in (known_assets.get("session_cookies") or []):
        if isinstance(c, dict) and c.get("name"):
            out[str(c["name"])] = str(c.get("value", ""))
    return out


def _spider_discovery_auth(crawl_cookies: dict | None) -> dict | None:
    """SP-1: assemble auth for the discovery re-fetch from the crawl's cookies +
    known_assets (latest JWT, captured session cookies). Returns
    ``{"headers", "cookies"}`` or None when nothing is known — so an anonymous
    scan behaves exactly as before, but a credentialed scan enriches under auth."""
    ka = (scan_session.get() or {}).get("known_assets") or {}
    cookies = _crawl_cookie_map(crawl_cookies)
    cookies.update(_session_cookie_map(ka))
    headers = _bearer_headers(ka)
    return {"headers": headers, "cookies": cookies} if (headers or cookies) else None


def _evaluate_spider_gate(target: str, raw: str) -> bool:
    """Did the spider actually run? Advances the failure-retry gate and returns the
    (possibly retry-released) ok flag."""
    spider_ok = _spider_succeeded(raw)
    current_retries = scan_session.get_spider_failures().get(target, {}).get("retry_count", 0)
    if spider_ok:
        scan_session.clear_spider_failure(target)
    elif current_retries >= scan_session.spider_max_retries():
        # After N retries still empty — assume non-crawlable target, release gate.
        scan_session.clear_spider_failure(target)
        log.note(f"spider: gate released for {target} after {current_retries + 1} attempts (treating as non-crawlable)")
        spider_ok = True
    else:
        new_count = scan_session.record_spider_failure(target)
        log.note(f"spider: GATE TRIGGERED for {target} — empty/error output (attempt {new_count})")
    return spider_ok


async def _spider_autodiscovery_note(target: str, raw: str, cookies: dict) -> str:
    """Auto-discovery enrichment: parse any OpenAPI/Swagger spec, mine JS bundles,
    read form fields, and AUTO-REGISTER the inventory into the coverage matrix.
    Shifts the model's job from "build the matrix" to "test the matrix". Returns a
    note to append ('' on nothing found / error). Fail-soft — never breaks spider."""
    try:
        from mcp_server.scan_engine.discovery import discover_and_register
        urls = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("http")]
        enrich = await discover_and_register(target, urls, auth=_spider_discovery_auth(cookies))
        log.note(f"spider auto-discovery: {enrich}")
        if enrich.get("registered"):
            src = ", ".join(f"{k}:{v}" for k, v in sorted(enrich["by_source"].items()))
            return (
                f"\n\n🧭 AUTO-DISCOVERY: registered {enrich['registered']} endpoint(s) / "
                f"{enrich['cells']} coverage cell(s) ({src})"
                + ("; OpenAPI/Swagger spec parsed and expanded" if enrich.get("spec_found") else "")
                + ".\nThe coverage matrix is now your test plan — you do NOT need to re-register "
                "these. Move to systematic per-cell testing (mark in_progress, run the tool, "
                "cite the artifact_id). If you discover further endpoints (JS, auth-gated pages), "
                "register them too before testing."
            )
    except Exception as exc:  # pragma: no cover - defensive
        log.note(f"spider auto-discovery skipped: {exc}")
    return ""


async def _handle_spider(target, flags, options):
    mode = options.get("mode", "fast")
    depth = str(max(1, options.get("depth", 3)))
    # Spider default raised from 15min → 2h (7200s) to handle large SPAs and
    # deep nav trees on enterprise targets. The MCP client timeout
    # (opencode.json "timeout" / claude mcp transport) must be at least this
    # large or the call will be cut by the client before the spider finishes
    # — installers/install*.sh now ship a 2.5h MCP client timeout for that
    # reason.
    timeout = options.get("timeout", 7200)
    cookies = options.get("cookies", {})
    max_pages = str(options.get("max_pages", 200))

    is_thorough = scan_session.get() and scan_session.get().get("depth") == "thorough"

    if is_thorough:
        # Thorough: run katana + playwright + ZAP AJAX spider, merge all results.
        log.tool_call("spider", {"url": target, "depth": depth, "mode": "thorough-all", "flags": flags})
        call_id = cost_tracker.start("spider")
        raw = await _run_spider_thorough(target, flags, cookies, depth, max_pages, timeout)
    else:
        log.tool_call("spider", {"url": target, "depth": depth, "mode": mode, "flags": flags})
        call_id = cost_tracker.start("spider")
        raw = await _run_spider_fast(target, flags, cookies, depth, max_pages, mode, timeout)

    _record("spider")
    # SP-11: `raw` is now the FULL crawl. Cost/log/summary reflect what actually
    # enters the model's context (the bounded envelope), not the whole crawl —
    # charging the full raw would inflate cost since the model never sees it.
    raw_summary = _clip(raw, 8_000)
    cost_tracker.finish(call_id, raw_summary)
    log.tool_result("spider", raw_summary)

    spider_ok = _evaluate_spider_gate(target, raw)

    from mcp_server.scan_engine import wrap
    # Bounded summary inline; FULL crawl retained as the on-disk artifact (SP-11).
    result = wrap("spider", raw_summary, {"url": target}, artifact_raw=raw)
    if not spider_ok:
        result += (
            "\n\n⚠️  SPIDER WARNING: Spider returned empty or error output. "
            "Other scan tools can still run on the original target + endpoints "
            "discovered by httpx/naabu/subfinder, but matrix coverage will be "
            "narrower than a full crawl would produce.\n"
            "Recommended:\n"
            "  1. If Kali is not running: session(action='start_kali')\n"
            f"  2. Retry: scan(tool='spider', target='{target}')\n"
            f"  (Failure tracking auto-releases after {scan_session.spider_max_retries()} retries.)"
        )
    else:
        result += await _spider_autodiscovery_note(target, raw, cookies)
    return result
