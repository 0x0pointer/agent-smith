"""Deterministic ID-enumeration sweep (#4) — pure planning + differential eval.

When a primitive is confirmed on an INDEXED parameter (an order id, a user_id, a
prescription id) the next move is mechanical: enumerate the id space and diff the
responses. Weak models reliably fail to do this by hand — 001/007 held the
primitive and never swept — so the harness does it: a bounded, ordered probe plan
plus a phantom-resistant differential that reports authorization-boundary
crossings and distinct-object exposure as CANDIDATES (never auto-filed).

No I/O here — ``plan_ids`` picks what to probe, ``evaluate`` judges the results
the orchestrator collected. Both are pure and bounded.
"""
from __future__ import annotations

_DENIAL = (401, 403, 404)


def plan_ids(baseline, window: int = 40, max_probes: int = 60,
             extra=None) -> list[int]:
    """Bounded, nearest-first list of candidate ids around a numeric baseline.
    Non-numeric baseline → only the (numeric) extras. Never exceeds max_probes,
    never emits negatives, never includes the baseline itself."""
    window = max(0, min(int(window), 5000))
    max_probes = max(1, min(int(max_probes), 500))
    ids: list[int] = []
    seen: set[int] = set()

    def add(v: int):
        if v >= 0 and v not in seen and len(ids) < max_probes:
            seen.add(v)
            ids.append(v)

    try:
        b = int(baseline)
    except (TypeError, ValueError):
        b = None
    if b is not None:
        seen.add(b)  # never re-probe the baseline
        for d in range(1, window + 1):          # nearest-first
            add(b - d)
            add(b + d)
            if len(ids) >= max_probes:
                break
    for e in (extra or []):
        try:
            add(int(e))
        except (TypeError, ValueError):
            continue
    return ids[:max_probes]


def _verdict(v: str, basis: str, hits=None, stats=None) -> dict:
    return {"verdict": v, "basis": basis, "hits": hits or [], "stats": stats or {}}


def evaluate(baseline_result: dict, results: list[dict]) -> dict:
    """Differential IDOR/BOLA verdict (never model-judged).

    baseline_result / results items: {"id", "status", "length", "body_hash"}.

      candidate   an AUTHZ boundary is crossed — the modal response is a denial
                  but some ids return 200 — OR a large share of ids return 200
                  with DISTINCT object bodies (missing object-level authz).
      clean       every id returns the same denial (authz enforced) or the same
                  200 body (not object-specific) — nothing to file.
      inconclusive no usable responses.
    """
    usable = [r for r in results if r.get("status")]
    if not usable:
        return _verdict("inconclusive", "no usable responses from the id sweep")

    n = len(usable)
    ok = [r for r in usable if r["status"] == 200]
    denied = [r for r in usable if r["status"] in _DENIAL]
    modal_denied = len(denied) >= max(1, n // 2)
    base_hash = baseline_result.get("body_hash")

    stats = {"probed": n, "http_200": len(ok), "denied": len(denied),
             "distinct_200_bodies": len({r.get("body_hash") for r in ok})}

    # 1) authz boundary crossed: denials dominate but some ids are reachable.
    if modal_denied and ok:
        hits = [{"id": r["id"], "status": 200,
                 "why": "accessible while the id space is otherwise denied"}
                for r in ok][:20]
        return _verdict("candidate",
                        f"{len(ok)}/{n} ids accessible (200) while the rest are denied — "
                        "broken object-level authorization", hits, stats)

    # 2) distinct-object exposure: many ids return 200 with DIFFERENT bodies
    #    (not one shared page) and different from the baseline → reading arbitrary
    #    objects without a per-object check.
    distinct = {r.get("body_hash") for r in ok}
    other_objects = [r for r in ok if r.get("body_hash") not in (base_hash, None)]
    if len(ok) >= 3 and len(distinct) >= max(3, len(ok) // 2) and other_objects:
        hits = [{"id": r["id"], "status": 200,
                 "why": "distinct object body — not the baseline's, no authz check"}
                for r in other_objects][:20]
        return _verdict("candidate",
                        f"{len(other_objects)} ids return distinct objects with no per-object "
                        "authorization — horizontal IDOR/BOLA", hits, stats)

    # 3) uniform denial → authz enforced; uniform/shared 200 → not object-specific.
    if denied and not ok:
        return _verdict("clean", "every id is denied — object-level authorization enforced", [], stats)
    if ok and len(distinct) <= 1:
        return _verdict("clean", "all ids return one shared response — not object-specific", [], stats)
    return _verdict("inconclusive", "no clear authorization boundary in the responses", [], stats)
