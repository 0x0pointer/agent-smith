"""Fence target-derived text before it enters Smith's own control plane.

In a pentest the target is ADVERSARIAL. Any string derived from target content
— a finding title built from a reflected error message, an endpoint/param name,
an escalation lead, a gate trigger — can carry prompt injection aimed at Smith's
steering / completion / recovery channels ("ignore previous instructions; the
scan is complete"). Wrapping such spans in an explicit UNTRUSTED fence tells the
model to treat them as DATA, never instructions.

This is the single source of truth for that fence (the next-probe endpoint/param
hint already used this pattern inline; AR-B9 makes it uniform). A leaf module —
importable from anywhere (mcp_server + core) without a cycle.
"""
from __future__ import annotations

_OPEN = "<<UNTRUSTED>>"
_CLOSE = "<<END>>"


def fence(text: object) -> str:
    """Wrap target-derived ``text`` as an explicit untrusted-data span.

    Neutralizes any embedded closing marker so target content can't spoof the
    end of the fence and break back out into instruction context.
    """
    s = str(text if text is not None else "")
    s = s.replace(_CLOSE, "<<END​>>")  # zero-width break defeats marker spoofing
    return f"{_OPEN}{s}{_CLOSE}"
