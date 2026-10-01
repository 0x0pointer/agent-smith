"""ZAP packaged-scan hook (issue #184) — inject the session into the Client Spider
and dump every discovered URL.

Loaded via `zap-baseline.py --hook=/zap/wrk/hook.py`. The packaged scans dispatch
hooks by FUNCTION NAME (docker/zap_common.py `trigger_hook`), so we implement the
two hook points we need:

  * zap_started(zap, target)  — add Replacer REQ_HEADER rules so EVERY request the
    browser-driven Client Spider makes carries the session (Bearer token / cookies).
    The auth values arrive via env vars (never written to disk / the image).
  * zap_pre_shutdown(zap)     — write the full sites-tree URL list, one per line, to
    /zap/wrk/urls.txt (this is what feeds agent-smith's endpoint discovery).

A Replacer REQ_HEADER rule operates at ZAP's HttpSender/proxy layer, so it reaches
the Client Spider's browser requests too (initiators=None = all initiators).
"""
import os

_WORK = "/zap/wrk"


def zap_started(zap, target):  # noqa: ARG001 (target unused; signature fixed by ZAP)
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
    try:
        with open(os.path.join(_WORK, "urls.txt"), "w") as fh:
            fh.write("\n".join(urls))
    except Exception:
        pass
