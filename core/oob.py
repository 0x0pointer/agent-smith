"""
Out-of-band (OOB) interaction helpers
=====================================
Pure command-building + output-parsing for the interactsh-client lifecycle. No
I/O lives here: the ``session()`` ``oob_start`` / ``oob_mint`` / ``oob_poll``
actions do the actual Kali exec, artifact writes, and known_assets registration.
Keeping the shell-command strings and the interactsh output parsing in a pure
module makes them unit-testable without a live collaborator server.

Backend is PLUGGABLE via ``OOB_MODE`` — interactsh is the default, not a
requirement:

  interactsh (default) — full DNS + HTTP(S) (+ SMTP) callbacks via the bundled
    interactsh-client. ``OOB_SERVER_URL`` blank → interactsh PUBLIC servers
    (oast.fun, …); set → ``-server <url>`` (your self-hosted interactsh-server);
    ``OOB_SERVER_TOKEN`` → ``-token`` for an auth-protected server. Catches the
    DNS-only callbacks that matter for egress-filtered / truly blind targets.

  http — ANY plain HTTP request logger (e.g. https://oob-logger.example.com,
    webhook.site, RequestBin, your own one-liner). ``OOB_SERVER_URL`` is the
    callback base; a unique correlation id is appended as a path so each test is
    attributable. Zero infra, but HTTP(S)-only (no DNS). Auto-polling needs an
    ``OOB_POLL_URL`` that returns the server's request log (use ``{id}`` to
    template the correlation id); without it, polling falls back to "check your
    server log" guidance.

  (Burp Collaborator is a natural third mode via Burp's REST API — left for a
  follow-up since it needs a managed Burp client.)

interactsh / http both sidestep NAT: nothing inbound is needed on the operator's
machine — the client connects OUTBOUND (interactsh) or the target calls the
public logger (http).
"""
from __future__ import annotations

import json
import re
import shlex

# Files inside the (persistent) Kali container's /tmp. The JSONL out-file holds
# interactions; the stdout log captures startup output incl. the minted domain.
OOB_OUT_FILE = "/tmp/oob_interactions.jsonl"
OOB_STDOUT_FILE = "/tmp/oob_client.log"
OOB_PID_FILE = "/tmp/oob_client.pid"

# A collaborator domain: a long random label followed by the server host. Matches
# both the public oast.* servers and a self-hosted server host.
_DOMAIN_RE = re.compile(r"\b[a-z0-9]{8,}\.[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}\b", re.IGNORECASE)
_LOG_PREFIXES = ("[inf]", "[err]", "[wrn]", "[ftl]", "[deb]")


def build_start_command(
    server_url: str = "",
    token: str = "",
    out_file: str = OOB_OUT_FILE,
    stdout_file: str = OOB_STDOUT_FILE,
    pid_file: str = OOB_PID_FILE,
) -> str:
    """Shell command that idempotently starts ONE backgrounded interactsh-client.

    A pidfile guards against starting a second client; ``-json -o`` streams
    interactions to ``out_file``; startup stdout (which carries the minted base
    domain) is captured to ``stdout_file``, which the command cats back so the
    caller can parse the domain.
    """
    flags = ["-json", "-o", shlex.quote(out_file)]
    if server_url.strip():
        flags += ["-server", shlex.quote(server_url.strip())]
    if token.strip():
        flags += ["-token", shlex.quote(token.strip())]
    flagstr = " ".join(flags)
    return (
        f'if [ -f {pid_file} ] && kill -0 "$(cat {pid_file})" 2>/dev/null; then '
        f"echo ALREADY_RUNNING; "
        f"else : > {out_file}; nohup interactsh-client {flagstr} > {stdout_file} 2>&1 & "
        f"echo $! > {pid_file}; sleep 3; fi; cat {stdout_file}"
    )


def build_poll_command(out_file: str = OOB_OUT_FILE) -> str:
    """Shell command to dump the interactions captured so far (JSONL)."""
    return f"cat {out_file} 2>/dev/null || true"


def build_stop_command(pid_file: str = OOB_PID_FILE) -> str:
    """Shell command to stop the listener and clear its pidfile."""
    return f'[ -f {pid_file} ] && kill "$(cat {pid_file})" 2>/dev/null; rm -f {pid_file}; echo STOPPED'


def parse_base_domain(stdout_text: str) -> str:
    """Extract the minted base collaborator domain from interactsh startup output.

    interactsh-client prints its banner, an ``[INF] Listing N payload …`` line,
    then the payload domain on its own line. Return the first domain-shaped token
    found (checked on every line, log-prefixed or not, to be robust to versions).
    """
    for line in stdout_text.splitlines():
        m = _DOMAIN_RE.search(line.strip())
        if m:
            return m.group(0)
    return ""


def mint_subdomain(base_domain: str, correlation_id: str) -> str:
    """Compose a unique callback host under the minted base domain.

    Any subdomain of the registered base routes back to the same client, so a
    unique label per test lets ``parse_interactions`` correlate a hit to the cell
    that fired it.
    """
    base = base_domain.strip().lstrip(".")
    return f"{correlation_id}.{base}" if base else correlation_id


def parse_interactions(jsonl_text: str, correlation_id: str = "") -> list[dict]:
    """Parse interactsh-client JSONL output into interaction dicts.

    When ``correlation_id`` is given, keep only lines that mention it (the minted
    label appears in the interaction's host / full-id / raw request), so a poll
    returns just the hits for the payload that was fired.
    """
    out: list[dict] = []
    needle = correlation_id.strip().lower()
    for line in jsonl_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        if needle and needle not in line.lower():
            continue
        try:
            out.append(json.loads(line))
        except (ValueError, TypeError):
            continue
    return out


# ── Backend selection + generic HTTP-logger mode ────────────────────────────────

def resolve_mode(mode_env: str = "") -> str:
    """Resolve the OOB backend: 'interactsh' (default) or 'http'.

    Explicit OOB_MODE wins; anything unrecognised (incl. blank) falls back to
    interactsh, which works against the public servers with no config.
    """
    m = (mode_env or "").strip().lower()
    return m if m in ("interactsh", "http") else "interactsh"


def mint_http_callback(base_url: str, correlation_id: str) -> str:
    """Compose a unique callback URL under a plain HTTP request logger.

    The correlation id is appended as a path segment so it shows up in the
    server's request log, letting a later poll correlate the hit to the test
    (e.g. base 'https://oob-logger.example.com' → '.../<id>').
    """
    base = base_url.strip().rstrip("/")
    return f"{base}/{correlation_id}" if base else correlation_id


def http_poll_url(poll_template: str, correlation_id: str) -> str:
    """Resolve the URL to fetch a generic logger's request log for a hit.

    A '{id}' placeholder is substituted with the correlation id; otherwise the
    template is used as-is (and the caller filters the response by id). Blank
    template → '' (no auto-poll endpoint configured → manual check).
    """
    t = (poll_template or "").strip()
    if not t:
        return ""
    return t.replace("{id}", correlation_id) if "{id}" in t else t


def build_http_poll_command(poll_url: str) -> str:
    """Kali curl command to fetch a generic logger's read endpoint."""
    return f"curl -s {shlex.quote(poll_url)} 2>/dev/null || true"


def parse_http_hits(text: str, correlation_id: str) -> list[dict]:
    """A generic logger 'hit' = the correlation id appears in the fetched log.

    Returns one entry per matching line so the poll handler can store the raw
    evidence as an artifact. Protocol is reported as http (this mode is
    HTTP-only by construction).
    """
    needle = correlation_id.strip().lower()
    if not needle:
        return []
    return [
        {"protocol": "http", "raw": line.strip()[:500]}
        for line in text.splitlines()
        if needle in line.lower()
    ]
