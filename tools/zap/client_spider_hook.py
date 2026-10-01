"""ZAP packaged-scan hook (issue #184) — inject the session into the Client Spider
and emit every discovered URL.

Loaded via `zap-baseline.py --hook=/zap/hook.py` (mounted READ-ONLY). The packaged
scans dispatch hooks by FUNCTION NAME (docker/zap_common.py `trigger_hook`), so we
implement the two hook points we need:

  * zap_started(zap, *args)  — add Replacer REQ_HEADER rules so EVERY request the
    browser-driven Client Spider makes carries the session (Bearer token / cookies).
    The auth values arrive via env vars (never written to disk / the image). ZAP
    calls this as zap_started(zap, target); we don't need `target`, hence *args.
  * zap_pre_shutdown(zap)    — print the full sites-tree URL list to STDOUT, framed by
    marker lines. The runner captures the container's stdout and parses the URLs out
    (so we need NO writable host mount — the hook is mounted read-only, avoiding loose
    directory permissions).

A Replacer REQ_HEADER rule operates at ZAP's HttpSender/proxy layer, so it reaches
the Client Spider's browser requests too (initiators=None = all initiators).
"""
import os

URLS_BEGIN = "=== SMITH_ZAP_URLS_BEGIN ==="
URLS_END = "=== SMITH_ZAP_URLS_END ==="


def zap_started(zap, *args):
    header = os.environ.get("SMITH_ZAP_AUTH_HEADER")      # e.g. "Bearer eyJ..."
    if header:
        zap.replacer.add_rule(
            description="smith-auth-authorization", enabled=True,
            matchtype="REQ_HEADER", matchregex=False, matchstring="Authorization",
            replacement=header, initiators=None,
        )
    cookie = os.environ.get("SMITH_ZAP_AUTH_COOKIE")      # e.g. "SESSION=..; csrf=.."
    if cookie:
        zap.replacer.add_rule(
            description="smith-auth-cookie", enabled=True,
            matchtype="REQ_HEADER", matchregex=False, matchstring="Cookie",
            replacement=cookie, initiators=None,
        )


def zap_pre_shutdown(zap):
    try:
        urls = zap.core.urls()                            # flat list of every discovered URL
    except Exception:
        urls = []
    print(URLS_BEGIN, flush=True)
    for url in urls:
        print(url, flush=True)
    print(URLS_END, flush=True)
