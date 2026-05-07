#!/usr/bin/env python3
"""
Playwright-based web spider with Hotwire/Turbo Frame support.

Crawls up to --depth levels using headless Chromium, injects session cookies,
waits for turbo-frame lazy-loaded content, and re-fetches every
<turbo-frame src=...> URL explicitly to capture dynamically loaded content.

Usage:
    playwright-spider --url https://example.com --depth 3
    playwright-spider --url https://example.com --cookies '{"_session_id":"abc"}' --depth 2
    playwright-spider --url https://example.com --max-pages 100
"""
import argparse
import asyncio
import json
import sys
from urllib.parse import urljoin, urlparse, urlunparse


def _same_origin(url: str, base_domain: str) -> bool:
    return urlparse(url).netloc == base_domain


def _normalise(url: str) -> str:
    """Strip query string and fragment so dedup works on canonical paths."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


async def spider(base_url: str, cookies: dict, depth: int, max_pages: int = 200) -> None:
    from playwright.async_api import async_playwright

    base_domain = urlparse(base_url).netloc
    visited: set[str] = set()
    found_urls: set[str] = set()
    found_forms: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            # --remote-debugging-port=0 → random ephemeral port (never 5000)
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--remote-debugging-port=0"],
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        if cookies:
            await context.add_cookies(
                [{"name": k, "value": v, "domain": base_domain, "path": "/"} for k, v in cookies.items()]
            )

        async def _fetch_page(url: str, timeout_ms: int = 30_000) -> object | None:
            page = await context.new_page()
            try:
                try:
                    await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                except Exception:
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms // 2)
                return page
            except Exception as exc:
                print(f"[warn] {url}: {exc}", file=sys.stderr)
                await page.close()
                return None

        async def _collect(page, base: str, current_depth: int) -> None:
            """Extract links, forms, and turbo-frame srcs from an open page."""
            # Turbo Frame srcs — re-fetch each one explicitly
            turbo_srcs: list[str] = await page.eval_on_selector_all(
                "turbo-frame[src]",
                "els => els.map(e => e.getAttribute('src')).filter(Boolean)",
            )
            for raw_src in turbo_srcs:
                full_src = urljoin(base, raw_src)
                if not _same_origin(full_src, base_domain):
                    continue
                norm_src = _normalise(full_src)
                found_urls.add(norm_src)
                if norm_src not in visited:
                    # Treat turbo-frame srcs as same depth — they are lazy loads, not navigation
                    queue.append((norm_src, current_depth))

            # Regular anchor links
            links: list[str] = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href).filter("
                "  h => h && !h.startsWith('mailto:') && !h.startsWith('javascript:')"
                ")",
            )
            for lnk in links:
                if _same_origin(lnk, base_domain):
                    found_urls.add(lnk)
                    if lnk not in visited and current_depth < depth:
                        queue.append((lnk, current_depth + 1))

            # Form actions
            form_actions: list[str] = await page.eval_on_selector_all(
                "form[action]",
                "els => els.map(e => e.getAttribute('action')).filter(Boolean)",
            )
            for act in form_actions:
                found_forms.add(urljoin(base, act))

        # BFS crawl
        while queue and len(visited) < max_pages:
            url, d = queue.pop(0)

            # Deduplicate — a URL may appear multiple times in the queue
            if url in visited:
                continue
            if not _same_origin(url, base_domain):
                continue

            visited.add(url)
            found_urls.add(url)

            page = await _fetch_page(url)
            if page is None:
                continue
            try:
                await _collect(page, url, d)
            finally:
                await page.close()

        await browser.close()

    for u in sorted(found_urls | found_forms):
        print(u)


def main() -> None:
    parser = argparse.ArgumentParser(description="Playwright-based web spider with Turbo Frame support")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cookies", default="{}", help="JSON dict of session cookies")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=200, help="Maximum pages to visit (default: 200)")
    args = parser.parse_args()

    try:
        cookies = json.loads(args.cookies)
    except json.JSONDecodeError as exc:
        print(f"[error] Invalid --cookies JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    asyncio.run(spider(args.url, cookies, args.depth, args.max_pages))


if __name__ == "__main__":
    main()
