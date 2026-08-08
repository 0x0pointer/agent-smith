"""Out-of-band (OAST) callback lifecycle: start / mint / poll."""


def _oob_config():
    """Read OOB backend config from env: (mode, server_url, token, poll_template)."""
    import os
    server = os.environ.get("OOB_SERVER_URL", "").strip()
    mode = _oob_module().resolve_mode(os.environ.get("OOB_MODE", ""))
    token = os.environ.get("OOB_SERVER_TOKEN", "").strip()
    poll_template = os.environ.get("OOB_POLL_URL", "").strip()
    return mode, server, token, poll_template


def _oob_module():
    from core import oob
    return oob


async def _do_oob_start():
    """Start/confirm the OOB backend. interactsh → launch the Kali client and
    return the minted domain; http → record the callback-logger base URL.

    Takes no options — the backend is configured entirely from env (_oob_config)."""
    from tools import kali_runner
    from core.session import assets as sess_assets
    oob = _oob_module()
    mode, server, token, poll_template = _oob_config()

    if mode == "http":
        if not server:
            return (
                "OOB_MODE=http needs OOB_SERVER_URL set to your HTTP request logger's base URL "
                "(e.g. https://oob-logger.example.com). Set it in .env and restart, or unset "
                "OOB_MODE to use interactsh's public servers."
            )
        sess_assets.set_oob_listener(server, mode="http", poll_url=poll_template)
        poll_note = (
            f"auto-poll via {poll_template}" if poll_template
            else "no OOB_POLL_URL set → polling will tell you to check the logger's own UI/logs"
        )
        return (
            f"OOB backend ready (mode=http, logger={server}; {poll_note}).\n"
            "Next: session(action='oob_mint', options={'cell_id': '<blind cell id>'}) to get a "
            "unique callback URL, embed it in your blind HTTP/SSRF payload, then "
            "session(action='oob_poll', options={'correlation_id': '<id>'}). NOTE: http mode is "
            "HTTP(S)-only — for DNS-based blind exfil use interactsh mode."
        )

    # interactsh mode
    cmd = oob.build_start_command(server_url=server, token=token)
    raw = await kali_runner.exec_command(cmd, timeout=60)
    base = oob.parse_base_domain(raw)
    if not base:
        return (
            "OOB listener start attempted, but no collaborator domain could be parsed from "
            "interactsh-client output. Check that the Kali container is up and OOB_SERVER_URL "
            "(if set) is reachable.\n--- interactsh output ---\n" + raw[:600]
        )
    sess_assets.set_oob_listener(base, out_file=oob.OOB_OUT_FILE, mode="interactsh")
    src = f"self-hosted {server}" if server else "public interactsh servers (oast.fun)"
    return (
        f"OOB listener ready (mode=interactsh, DNS+HTTP). Base collaborator domain: {base}  "
        f"(server: {src}).\n"
        "Next: session(action='oob_mint', options={'cell_id': '<blind cell id>'}) to get a unique "
        "callback host, embed it in your blind payload (SSRF/RCE/XXE/OAST-SQLi/DNS exfil), then "
        "session(action='oob_poll', options={'correlation_id': '<id>'}) to confirm the callback."
    )


def _do_oob_mint(opts):
    """Mint a unique callback (subdomain for interactsh, URL for http) under the
    active listener. Pure session-state work — no I/O, hence not async."""
    import uuid
    from datetime import datetime, timezone
    from core.session import assets as sess_assets
    oob = _oob_module()

    listener = sess_assets.get_oob_listener()
    base = (listener or {}).get("base_domain", "")
    if not base:
        return "No OOB listener running. Call session(action='oob_start') first."
    mode = (listener or {}).get("mode", "interactsh")
    correlation_id = uuid.uuid4().hex[:12]
    if mode == "http":
        callback = oob.mint_http_callback(base, correlation_id)
        embed_hint = f"Embed this URL in your blind HTTP/SSRF payload: {callback}"
    else:
        callback = oob.mint_subdomain(base, correlation_id)
        embed_hint = (
            f"Embed it in your blind payload — e.g. http://{callback}/ , a DNS lookup of "
            f"{callback}, or an XXE/SSRF target."
        )
    sess_assets.update_known_assets("oob_interactions", [{
        "subdomain": callback,
        "correlation_id": correlation_id,
        "linked_cell_id": str(opts.get("cell_id", "")),
        "minted_at": datetime.now(timezone.utc).isoformat(),
        "polled": False,
        "hits": 0,
    }])
    return (
        f"OOB callback minted: {callback}  (correlation_id={correlation_id}).\n"
        f"{embed_hint}\n"
        f"After firing, run session(action='oob_poll', options={{'correlation_id': "
        f"'{correlation_id}'}}). Registered in known_assets so it survives context compaction."
    )


async def _do_oob_poll(opts):
    """Poll the active backend for interactions matching a minted correlation id."""
    import json as _json
    from tools import kali_runner
    from core.session import assets as sess_assets
    from mcp_server.scan_engine.artifacts import store_artifact
    oob = _oob_module()

    correlation_id = str(opts.get("correlation_id", "")).strip()
    if not correlation_id:
        return "Missing correlation_id. Use the id returned by session(action='oob_mint')."
    listener = sess_assets.get_oob_listener()
    mode = (listener or {}).get("mode", "interactsh")

    if mode == "http":
        poll_url = oob.http_poll_url((listener or {}).get("poll_url", ""), correlation_id)
        if not poll_url:
            base = (listener or {}).get("base_domain", "")
            return (
                f"This OOB logger ({base}) has no OOB_POLL_URL configured, so the callback can't "
                f"be fetched automatically. Check the logger's own UI/logs for a request to a path "
                f"containing '{correlation_id}'. If it arrived, that confirms the blind vuln — save "
                "the log line as a PoC and file the finding."
            )
        raw = await kali_runner.exec_command(oob.build_http_poll_command(poll_url), timeout=30)
        hits = oob.parse_http_hits(raw, correlation_id)
    else:
        out_file = (listener or {}).get("out_file", oob.OOB_OUT_FILE)
        raw = await kali_runner.exec_command(oob.build_poll_command(out_file), timeout=30)
        hits = oob.parse_interactions(raw, correlation_id)

    sess_assets.mark_oob_polled(correlation_id, len(hits))
    if not hits:
        return (
            f"No OOB interactions for correlation_id={correlation_id} yet. Blind callbacks can "
            "lag — if you just fired the payload, wait and poll again. No callback after a "
            "reasonable wait is evidence the injection did NOT reach an OOB sink."
        )
    artifact_id = store_artifact("oob_interaction", _json.dumps(hits, indent=2))
    protos = ", ".join(sorted({str(h.get("protocol", "?")) for h in hits}))
    return (
        f"OOB CONFIRMED: {len(hits)} interaction(s) for {correlation_id} (protocols: {protos}). "
        f"artifact_id={artifact_id}. This is proof of a blind vulnerability — file "
        "report(action='finding', ...) for it, then close the blind cell vulnerable with this "
        "artifact_id and the returned finding_id."
    )
