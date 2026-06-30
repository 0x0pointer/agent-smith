"""
Incremental session-state accumulation.

Three peripheral mutators of session ``_current``: the tool-invocation log
(dedup + recovery), the known-assets vault (domains/ips/ports/credentials/
tokens/endpoints), and the spider-failure gate (blocks other tools until a
failed spider is retried, auto-releasing after _SPIDER_MAX_RETRIES). All read
and persist ``_current`` through ``core.session`` (the ``_sess`` alias).
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.session as _sess

# ── Spider failure gate ───────────────────────────────────────────────────────
# Any failure blocks all other scan tools until spider is retried successfully.
# Auto-releases after _SPIDER_MAX_RETRIES attempts so a genuinely non-crawlable
# target doesn't loop forever.
_SPIDER_MAX_RETRIES = 3


def add_tool_invocation(tool: str, target: str, summary: str, options_hash: str = "") -> None:
    """Record a tool invocation with summary for dedup and recovery."""
    if not _sess._current or _sess._current.get("status") != "running":
        return
    invocations = _sess._current.setdefault("tool_invocations", [])
    if options_hash and any(i.get("options_hash") == options_hash for i in invocations):
        return  # Duplicate — already recorded
    invocations.append({
        "seq": len(invocations) + 1,
        "tool": tool,
        "target": target,
        "options_hash": options_hash,
        "summary": summary[:200],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    if len(invocations) > 100:
        _sess._current["tool_invocations"] = invocations[-100:]
    _sess._flush()


def set_last_artifact(tool: str, artifact_id: str) -> None:
    """Stash the most-recent tool artifact id so a finding filed right after a
    proving tool call can auto-link its evidence artifact.

    This is what lets adjudication REUSE the testing-phase proof instead of
    forcing the model to re-run the attack (it has lost the exact artifact_id to
    context compaction). Only scan/http/kali tools reach wrap(), so this never
    points at a report/coverage call.
    """
    if not _sess._current or _sess._current.get("status") != "running" or not artifact_id:
        return
    _sess._current["last_artifact_id"] = artifact_id
    _sess._current.setdefault("last_artifacts_by_tool", {})[tool] = artifact_id
    _sess._flush()


def _update_ports_assets(assets: dict, items: list) -> None:
    """Deduplicate and append port entries to known_assets['ports']."""
    existing = {(p.get("host", ""), p.get("port", 0)) for p in assets.get("ports", [])}
    for item in items:
        if isinstance(item, dict):
            key = (item.get("host", ""), item.get("port", 0))
            if key not in existing:
                assets.setdefault("ports", []).append(item)
                existing.add(key)


def _update_scalar_assets(assets: dict, asset_type: str, items: list) -> None:
    """Deduplicate and append string/scalar entries to a known_assets list."""
    target_list = assets.setdefault(asset_type, [])
    existing = set(target_list)
    for item in items:
        val = item if isinstance(item, str) else str(item)
        if val and val not in existing:
            target_list.append(val)
            existing.add(val)


def _update_dict_assets(assets: dict, asset_type: str, items: list, dedup_keys: tuple[str, ...]) -> None:
    """Deduplicate and append dict entries (credentials, tokens, endpoints) by composite key."""
    target_list = assets.setdefault(asset_type, [])
    existing = {tuple(e.get(k, "") for k in dedup_keys) for e in target_list if isinstance(e, dict)}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = tuple(item.get(k, "") for k in dedup_keys)
        if any(key) and key not in existing:
            target_list.append(item)
            existing.add(key)


def update_known_assets(asset_type: str, items: list) -> None:
    """Accumulate discovered assets into session.json['known_assets']."""
    if not _sess._current or _sess._current.get("status") != "running" or not items:
        return
    assets = _sess._current.setdefault("known_assets", {
        "domains": [], "ips": [], "ports": [],
        "technologies": [], "endpoints": [],
        "credentials": [], "auth_tokens": [], "auth_endpoints": [],
        "oob_interactions": [],
    })
    if asset_type == "ports":
        _update_ports_assets(assets, items)
    elif asset_type == "credentials":
        _update_dict_assets(assets, asset_type, items, ("username",))
    elif asset_type == "auth_tokens":
        _update_dict_assets(assets, asset_type, items, ("value",))
    elif asset_type == "auth_endpoints":
        _update_dict_assets(assets, asset_type, items, ("path", "method"))
    elif asset_type == "oob_interactions":
        _update_dict_assets(assets, asset_type, items, ("correlation_id",))
    else:
        _update_scalar_assets(assets, asset_type, items)
    _sess._flush()


# ── Out-of-band (OOB) collaborator state ───────────────────────────────────────
# The minted listener domain + the minted-callback registry live in session
# state so a blind-vuln callback fired in one turn can be polled many turns
# later — and survives context compaction via the recovery brief's known_assets.

def set_oob_listener(
    base_domain: str,
    out_file: str = "",
    mode: str = "interactsh",
    poll_url: str = "",
) -> None:
    """Record the active OOB listener.

    ``mode`` = interactsh|http. For interactsh, ``base_domain`` is the minted
    collaborator domain and ``out_file`` the interactions JSONL path. For http,
    ``base_domain`` is the callback base URL and ``poll_url`` the optional log
    read-endpoint template.
    """
    if not _sess._current or _sess._current.get("status") != "running":
        return
    _sess._current["oob_listener"] = {
        "mode": mode,
        "base_domain": base_domain,
        "out_file": out_file,
        "poll_url": poll_url,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _sess._flush()


def get_oob_listener() -> dict | None:
    """Return the active OOB listener record, or None if none is running."""
    if _sess._current is None:
        return None
    return _sess._current.get("oob_listener")


def mark_oob_polled(correlation_id: str, hits: int) -> None:
    """Mark a minted OOB callback as polled, recording the hit count.

    Lets the QA daemon distinguish a fired-but-never-polled callback (a blind
    vuln left unconfirmed) from one that has been checked.
    """
    if _sess._current is None:
        return
    entries = (_sess._current.get("known_assets") or {}).get("oob_interactions") or []
    changed = False
    for e in entries:
        if isinstance(e, dict) and e.get("correlation_id") == correlation_id:
            e["polled"] = True
            e["hits"] = hits
            e["last_polled_at"] = datetime.now(timezone.utc).isoformat()
            changed = True
    if changed:
        _sess._flush()


def record_spider_failure(target: str) -> int:
    """Record a spider failure for this target.  Returns the new retry count."""
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current.get("status") != "running":
        return 0
    failures = _sess._current.setdefault("spider_failures", {})
    entry = failures.get(target, {})
    new_count = entry.get("retry_count", 0) + 1
    failures[target] = {
        "target": target,
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "retry_count": new_count,
    }
    _sess._flush()
    return new_count


def clear_spider_failure(target: str) -> None:
    """Clear spider failure for this target after a successful run."""
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return
    failures = _sess._current.get("spider_failures")
    if failures and target in failures:
        del failures[target]
        _sess._flush()


def has_spider_failure() -> bool:
    """Return True if any spider has failed and not yet recovered."""
    if _sess._current is None:
        return False
    return bool(_sess._current.get("spider_failures"))


def get_spider_failures() -> dict:
    """Return all current spider failure entries keyed by target URL."""
    if _sess._current is None:
        return {}
    return dict(_sess._current.get("spider_failures", {}))


def spider_max_retries() -> int:
    return _SPIDER_MAX_RETRIES
