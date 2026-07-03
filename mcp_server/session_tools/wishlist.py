"""Non-blocking agent->operator wishlist backlog."""
import json

from core import logger as log
from core import session as scan_session


# ── Wishlist: non-blocking agent→operator backlog ──────────────────────────────
# Terms that mean "I want auth Smith may already hold". A wishlist for these is
# rejected when known_assets already has usable auth — so Smith can't quietly
# route around the 401/403 re-test gate by asking the operator for creds.
_AUTH_NEED_TERMS = (
    "credential", "password", "login as", "auth token", "jwt", "bearer token",
    "api key", "apikey", "session token", "valid account", "sign in", "sign-in", "log in",
)


def _wishlist_already_satisfiable(need: str) -> str | None:
    """If the need is for auth Smith already holds, point at known_assets instead.

    Closes the moral-hazard hole: without this, Smith could wishlist 'admin creds'
    to sidestep the auth re-test gate rather than using auth already captured.
    """
    n = need.lower()
    if not any(t in n for t in _AUTH_NEED_TERMS):
        return None
    ka = (scan_session.get() or {}).get("known_assets", {})
    have: list[str] = []
    if ka.get("credentials"):
        have.append(f"{len(ka['credentials'])} credential pair(s)")
    if ka.get("auth_tokens"):
        have.append(f"{len(ka['auth_tokens'])} JWT/token(s)")
    if ka.get("auth_endpoints"):
        have.append(f"{len(ka['auth_endpoints'])} login endpoint(s)")
    if not have:
        return None
    return (
        "NOT QUEUED — you already hold auth context for this target: " + ", ".join(have) + ". "
        "Use it instead of asking the operator: attach the JWT as 'Authorization: Bearer <value>' "
        "(see session(action='recovery') → auth_context), or POST known credentials to a login "
        "endpoint to mint a fresh token. Only wishlist auth if those are exhausted/expired — and "
        "say so in the rationale."
    )


def _do_wishlist_add(opts):
    from core.wishlist import wishlist_queue
    need = str(opts.get("need", "")).strip()
    if not need:
        return (
            "wishlist_add requires need= — what you need to go deeper "
            "(e.g. 'valid analyst-role creds to reach /admin', 'scope expanded to the staging API', "
            "'rate-limit relief on the login endpoint'). Optional: category= "
            "(credentials|scope|rate_limit|tooling|access|environment|other), rationale=, "
            "blocking_cell_ids=[...]."
        )
    guard = _wishlist_already_satisfiable(need)
    if guard:
        return guard
    blocking = opts.get("blocking_cell_ids") or []
    item_id = wishlist_queue.add(
        need=need,
        category=str(opts.get("category", "other")),
        rationale=str(opts.get("rationale", "")),
        blocking_cell_ids=blocking if isinstance(blocking, list) else [],
    )
    if item_id is None:
        return "Already on the wishlist (an open item with this need exists) — not duplicated."
    log.note(f"wishlist add: {need}")
    link = f" Linked to {len(blocking)} blocked cell(s)." if blocking else ""
    return (
        f"Wishlist item {item_id} recorded (NON-BLOCKING) — the operator sees it on the dashboard "
        f"and can fulfill it without pausing the scan.{link} Keep testing other coverage; do NOT "
        "mark the blocked cells not_applicable just because the resource is missing — they stay "
        "pending until the need is fulfilled."
    )


def _do_wishlist_list():
    from core.wishlist import wishlist_queue
    open_items = wishlist_queue.list_open()
    return json.dumps({
        "open": len(open_items),
        "items": [
            {
                "id": i.id, "need": i.need, "category": i.category,
                "rationale": i.rationale, "blocking_cell_ids": i.blocking_cell_ids,
            }
            for i in open_items
        ],
    }, indent=2)
