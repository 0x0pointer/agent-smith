"""Pure-Python payload-transforms engine for AI red-teaming.

A clean-room reimplementation of the *techniques* in Arcanum-Sec/P4RS3LT0NGV3
(encodings, ciphers, homoglyphs, invisible-Unicode smuggling, plus higher-order
generators). Zero third-party dependencies, no Docker/subprocess — it runs
in-process — nothing to pull, install, or time out.

Exposed to the agent as the ``transform()`` MCP tool (mcp_server/transform_tools.py).
"""
from __future__ import annotations

from . import generators
from .registry import (
    CATEGORIES,
    REVERSIBLE,
    TRANSFORMS,
    decode,
    encode,
    list_transforms,
)

__all__ = [
    "TRANSFORMS", "CATEGORIES", "REVERSIBLE",
    "encode", "decode", "list_transforms", "generators",
]
