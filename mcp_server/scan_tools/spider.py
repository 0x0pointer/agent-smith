"""Spider handler: fast/playwright/deep modes + thorough (katana+playwright+ZAP)."""
import shlex

from core import cost as cost_tracker
from core import logger as log
from core import session as scan_session
from mcp_server._app import _clip, _record
from ._common import _spider_succeeded


async def _run_spider_thorough(target: str, flags: str, cookies: dict, depth: str, max_pages: str, timeout: int) -> str:
    """Run katana + playwright + ZAP AJAX spider in thorough mode and return merged raw output."""
    import asyncio as _asyncio
    from tools import kali_runner
    import json as _json

    safe_url = shlex.quote(target)
    safe_cookies = shlex.quote(_json.dumps(cookies))
    # Split the budget across the 3 subtools so total wall-clock caps at the
    # user-provided `timeout` value (default 2h → ~40min per subtool, floor
    # 20min so a tiny budget doesn't starve any one tool).
    per_subtool = max(timeout // 3, 1200)
    log.note(f"spider: thorough mode — katana + playwright + zap-ajax (per-subtool timeout={per_subtool}s)")

    safe_flags = shlex.join(shlex.split(flags)) if flags else ""
    rate_flag = "" if "-rate-limit" in (flags or "") else "-rate-limit 50"
    katana_cmd = f"katana -u {safe_url} -d {depth} -silent -no-color {rate_flag}".strip()
    if safe_flags:
        katana_cmd += f" {safe_flags}"

    playwright_cmd = (
        f"playwright-spider --url {safe_url} --cookies {safe_cookies} "
        f"--depth {depth} --max-pages {max_pages}"
    )

    # Guard zap-cli: it isn't present in every Kali image build. Without this guard a
    # missing binary leaks "zap-cli: command not found" into the merged spider output
    # and muddies the result — skip the ZAP AJAX sub-tool cleanly instead.
    zap_cmd = (
        f"if command -v zap-cli >/dev/null 2>&1; then "
        f"zap-cli --port 8090 --api-key zapscan quick-scan --spider --ajax-spider "
        f"--start-options '-config api.key=zapscan -port 8090' {safe_url}; "
        f"else echo '[zap-ajax skipped: zap-cli not installed in the Kali image]'; fi"
    )

    parts = []
    for label, cmd, t in [
        ("=== katana ===", katana_cmd, per_subtool),
        ("=== playwright ===", playwright_cmd, per_subtool),
        ("=== zap-ajax ===", zap_cmd, per_subtool),
    ]:
        async with _asyncio.timeout(t):
            out = _clip(await kali_runner.exec_command(cmd), 4_000)
        parts.append(f"{label}\n{out}")

    return "\n\n".join(parts)


async def _run_spider_fast(target: str, flags: str, cookies: dict, depth: str, max_pages: str, mode: str, timeout: int) -> str:
    """Run the fast/playwright/deep spider mode and return raw output."""
    import asyncio as _asyncio
    from tools import kali_runner
    import json as _json

    safe_url = shlex.quote(target)
    safe_cookies = shlex.quote(_json.dumps(cookies))

    if mode == "playwright":
        cmd = (
            f"playwright-spider --url {safe_url} --cookies {safe_cookies} "
            f"--depth {depth} --max-pages {max_pages}"
        )
    elif mode == "deep":
        cmd = (
            f"if command -v zap-cli >/dev/null 2>&1; then "
            f"zap-cli --port 8090 --api-key zapscan quick-scan --spider --ajax-spider "
            f"--start-options '-config api.key=zapscan -port 8090' {safe_url}; "
            f"else echo '[zap-ajax skipped: zap-cli not installed in the Kali image]'; fi"
        )
    else:
        safe_flags = shlex.join(shlex.split(flags)) if flags else ""
        rate_flag = "" if "-rate-limit" in (flags or "") else "-rate-limit 50"
        cmd = f"katana -u {safe_url} -d {depth} -silent -no-color {rate_flag}".strip()
        if safe_flags:
            cmd += f" {safe_flags}"

    async with _asyncio.timeout(timeout):
        return _clip(await kali_runner.exec_command(cmd), 8_000)


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
    cost_tracker.finish(call_id, raw)
    log.tool_result("spider", raw)

    # Spider gate: detect whether the tool actually ran.
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

    from mcp_server.scan_engine import wrap
    result = wrap("spider", raw, {"url": target})
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
        # Auto-discovery enrichment: parse any OpenAPI/Swagger spec, mine JS
        # bundles, read form fields, and AUTO-REGISTER the whole inventory into
        # the coverage matrix. Shifts the model's job from "build the matrix"
        # (which weaker models skip, leaving stub endpoints) to "test the
        # matrix". Fail-soft — never break the spider result on enrichment error.
        try:
            from mcp_server.scan_engine.discovery import discover_and_register
            urls = [ln.strip() for ln in raw.splitlines() if ln.strip().startswith("http")]
            enrich = await discover_and_register(target, urls)
            log.note(f"spider auto-discovery: {enrich}")
            if enrich.get("registered"):
                src = ", ".join(f"{k}:{v}" for k, v in sorted(enrich["by_source"].items()))
                result += (
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
    return result
