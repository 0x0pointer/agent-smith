"""
QA agent — Human-Intervention-Required (HIR) trigger.

``_hir`` is the single entry point every HIR check uses to pause the scan.
It reads the dedup state (``_last_hir_trigger_ts``) and the min-gap floor
(``_HIR_MIN_GAP_SECONDS``) from the package namespace so tests that reset
``core.qa_agent._last_hir_trigger_ts`` take effect.
"""
from __future__ import annotations

import core.qa_agent as _qa


def _hir(code: str, situation: str, tried: list[str], options: list[str]) -> None:
    """Trigger HIR if one is not already active. Always fires regardless of scan mode.

    Two-layer dedup:

      1. ``get_intervention()`` — primary check. Pre-fix this read a
         cached ``_current`` and could miss a freshly-triggered HIR in
         the same QA cycle when multiple checks fire back-to-back.
         Post-fix it force-reloads session.json mtime first.

      2. ``_HIR_MIN_GAP_SECONDS`` floor — backstop. Even if layer 1
         were ever defeated again, this prevents the same HIR code from
         re-triggering within 60s, which kills the "Stuck Events" dash
         flood the user reported (5 HIRs in 137ms).
    """
    import time as _time
    now = _time.time()
    last = _qa._last_hir_trigger_ts.get(code, 0.0)
    if now - last < _qa._HIR_MIN_GAP_SECONDS:
        return
    try:
        from core import session as scan_session
        if not scan_session.get_intervention():
            scan_session.trigger_intervention(code, situation, tried, options)
            _qa._last_hir_trigger_ts[code] = now
    except Exception:
        pass
