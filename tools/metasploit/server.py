#!/usr/bin/env python3
"""
Thin Flask API for the Metasploit container.
Mirrors the kali-server-mcp interface so metasploit_runner.py works
with the same HTTP pattern.

Security: This server intentionally executes arbitrary commands as root — it is the
command-execution API for an isolated Docker container. It is defended in depth:
  * loopback-only Docker publish (127.0.0.1:5002:5000) — not reachable from the LAN;
  * a Host allowlist (below) — rejects any Host not localhost/127.0.0.1, which defeats
    DNS rebinding (a rebound request carries the attacker's Host);
  * a shared-secret token (MSF_API_SECRET / X-API-Secret) — metasploit_runner mints and
    sends it, so a local process / rebinding page that reaches loopback still can't drive it;
  * application/json is REQUIRED (no force-parse) — so a browser "simple request" CSRF
    (text/plain, form-encoded) is rejected before it can execute.

Endpoints:
  GET  /health      — liveness check
  POST /api/command — run a shell command, return stdout/stderr/timed_out
"""
import os
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)  # NOSONAR — stateless JSON API, no cookies/sessions; loopback + Host allowlist + token

# Shared secret — when MSF_API_SECRET is set (metasploit_runner always sets it), every
# /api/command request must carry it in X-API-Secret.
_API_SECRET = os.environ.get("MSF_API_SECRET", "")

# Only these Host header hostnames may reach the API. A DNS-rebinding page's request
# arrives with the attacker's domain in Host, so it is rejected here.
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "metasploit", "pentest-metasploit"}


@app.before_request
def _host_guard():
    host = (request.host or "").split(":")[0].strip().lower()
    if host not in _ALLOWED_HOSTS:
        return jsonify({"error": "forbidden host"}), 421


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/command", methods=["POST"])
def run_command():
    if _API_SECRET and request.headers.get("X-API-Secret") != _API_SECRET:
        return jsonify({"error": "unauthorized"}), 403

    # Require application/json — do NOT force-parse. A cross-origin browser CSRF can only
    # send "simple" content-types (text/plain, form-encoded) without a preflight; rejecting
    # those here means such a request can never reach the command execution below.
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "expected application/json"}), 415
    command = data.get("command", "")
    timeout = data.get("timeout", 900)

    if not command:
        return jsonify({"error": "empty command"}), 400

    try:
        result = subprocess.run(
            ["bash", "-c", command],  # nosec B603 — intentional command execution in isolated container  # NOSONAR
            capture_output=True,
            timeout=timeout,
        )
        return jsonify({
            "stdout": result.stdout.decode(errors="replace"),
            "stderr": result.stderr.decode(errors="replace"),
            "timed_out": False,
        })
    except subprocess.TimeoutExpired as exc:
        return jsonify({
            "stdout": exc.stdout.decode(errors="replace") if exc.stdout else "",
            "stderr": exc.stderr.decode(errors="replace") if exc.stderr else "",
            "timed_out": True,
        })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # NOSONAR — must bind 0.0.0.0 inside Docker for port mapping
