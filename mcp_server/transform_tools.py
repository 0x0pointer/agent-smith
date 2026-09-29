"""Consolidated payload-transforms tool — `transform()`.

A pure-Python, in-process crafting primitive for AI red-teaming: encode / mutate
/ chain a jailbreak or prompt-injection payload into a form that slips past LLM
input filters and safety classifiers, then decode an obfuscated model reply. No
Docker, npm, pip, or API keys — nothing to pull, install, or time out.

Typical loop:  craft text  ->  transform(action="encode"/"mutate"/"bijection")
->  http(action="request") to deliver  ->  transform(action="decode") on the reply.
"""
from __future__ import annotations

import json

from core import logger as log
from mcp_server._app import mcp, _ensure_dict, _record
from mcp_server.transforms import (
    CATEGORIES,
    TRANSFORMS,
    generators,
    list_transforms,
)
from mcp_server.transforms import encode as _encode_chain
from mcp_server.transforms import decode as _decode_chain
from mcp_server.transforms import invisible as _invisible

# Inline output cap — big payloads (token-bombs, large mutation sets) are stored
# as artifacts and only previewed inline so context/cost stay bounded.
_INLINE_CAP = 4_000


def _maybe_artifact(tool_label: str, raw: str, save: bool) -> str | None:
    if not save:
        return None
    from mcp_server.scan_engine.artifacts import store_artifact
    return store_artifact(tool_label, raw)


@mcp.tool()
async def transform(action: str, text: str = "", options: dict | str | None = None) -> str:
    """Craft, mutate, or decode obfuscated LLM payloads (P4RS3LT0NGV3-style).

    action : list | encode | decode | mutate | bijection | tokenbomb | steg
    text   : the payload / ciphertext to operate on
    options: action-specific settings (dict)

    list      — available transforms.  options: category=
    encode    — apply a transform chain.  options: transforms=[...], save_artifact=false
    decode    — reverse a known chain (transforms=[...]) OR auto-detect if omitted
    mutate    — N obfuscated variants (fuzzer).  options: count=10, techniques=[...], seed=, save_artifact=false
    bijection — Bijection-Learning jailbreak scaffold.  options: mapping_type=letters|digits|tokens, alphabet_size=26, seed=
    tokenbomb — token-exhaustion payload (LLM10).  options: size=200, seed=, save_artifact=true
    steg      — hide/reveal via invisible Unicode.  options: mode=hide|reveal, method=variation_selector|zero_width|unicode_tags, carrier=

    Categories: base, cipher, radio, homoglyph, invisible, script, word, case.
    """
    opts = _ensure_dict(options) or {}
    _record("transform")  # count as AI red-team work for coverage/skill-worked gates
    log.tool_call("transform", {"action": action, "text_len": len(text or ""), "options": opts})
    try:
        result = _dispatch(action, text or "", opts)
    except KeyError as exc:
        result = json.dumps({"error": f"unknown transform {exc}"})
    except ValueError as exc:
        result = json.dumps({"error": str(exc)})
    except Exception as exc:  # fail-soft — never crash the agent's turn
        result = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    log.tool_result("transform", result)
    return result


def _do_list(text, opts):
    items = list_transforms(opts.get("category"))
    return json.dumps({"count": len(items), "categories": CATEGORIES, "transforms": items}, indent=2)


def _do_encode(text, opts):
    names = opts.get("transforms") or []
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    if not names:
        return json.dumps({"error": "encode requires options.transforms=[...]"})
    out = _encode_chain(text, names)
    art = _maybe_artifact("transform", out, opts.get("save_artifact", False))
    return json.dumps({"transforms": names, "input_len": len(text),
                       "output": out[:_INLINE_CAP], "output_len": len(out),
                       "truncated": len(out) > _INLINE_CAP, "artifact_id": art})


def _do_decode(text, opts):
    names = opts.get("transforms")
    if names:
        if isinstance(names, str):
            names = [n.strip() for n in names.split(",") if n.strip()]
        out = _decode_chain(text, names)
        return json.dumps({"mode": "chain", "transforms": names, "output": out[:_INLINE_CAP]})
    ud = generators.universal_decode(text, max_candidates=opts.get("max_candidates", 6))
    return json.dumps({"mode": "auto", **ud}, indent=2)


def _do_mutate(text, opts):
    variants = generators.mutate(
        text,
        count=int(opts.get("count", 10)),
        techniques=opts.get("techniques"),
        seed=opts.get("seed"),
    )
    art = _maybe_artifact("transform", json.dumps(variants), opts.get("save_artifact", False))
    preview = [{"chain": v["chain"], "payload": v["payload"][:400]} for v in variants]
    return json.dumps({"count": len(variants), "variants": preview, "artifact_id": art}, indent=2)


def _do_bijection(text, opts):
    scaffold = generators.bijection_scaffold(
        text,
        mapping_type=opts.get("mapping_type", "letters"),
        alphabet_size=int(opts.get("alphabet_size", 26)),
        seed=opts.get("seed"),
    )
    return json.dumps(scaffold, indent=2)


def _do_tokenbomb(text, opts):
    tb = generators.tokenbomb(size=int(opts.get("size", 200)), seed=opts.get("seed"))
    art = _maybe_artifact("transform", tb["payload"], opts.get("save_artifact", True))
    return json.dumps({"char_count": tb["char_count"], "note": tb["note"],
                       "payload": tb["payload"][:_INLINE_CAP],
                       "truncated": tb["char_count"] > _INLINE_CAP, "artifact_id": art})


def _do_steg(text, opts):
    mode = opts.get("mode", "hide")
    method = opts.get("method", "variation_selector")
    if mode == "reveal":
        return json.dumps({"mode": "reveal", "hidden": _invisible.extract_hidden(text)})
    if method == "variation_selector":
        out = _invisible.steg_hide(text, opts.get("carrier", chr(0x1F600)))
    elif method == "zero_width":
        out = _invisible.zero_width_encode(text)
    elif method == "unicode_tags":
        out = _invisible.tags_encode(text)
    else:
        return json.dumps({"error": f"unknown steg method '{method}'"})
    art = _maybe_artifact("transform", out, opts.get("save_artifact", False))
    return json.dumps({"mode": "hide", "method": method, "output": out,
                       "renders_visibly": method == "variation_selector", "artifact_id": art})


_DISPATCH = {"list": _do_list, "encode": _do_encode, "decode": _do_decode, "mutate": _do_mutate,
             "bijection": _do_bijection, "tokenbomb": _do_tokenbomb, "steg": _do_steg}


def _dispatch(action: str, text: str, opts: dict) -> str:
    fn = _DISPATCH.get(action)
    if fn is None:
        return json.dumps({"error": f"unknown action '{action}'. Use: " + ", ".join(_DISPATCH)})
    return fn(text, opts)
