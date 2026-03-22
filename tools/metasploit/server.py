#!/usr/bin/env python3
"""
Thin Flask API for the Metasploit container.
Mirrors the kali-server-mcp interface so metasploit_runner.py works
with the same HTTP pattern.

Security: This server intentionally executes arbitrary commands — it is
the command execution API for an isolated Docker container that only
binds to 127.0.0.1 on the host (via Docker port mapping). The container
runs in a disposable, --rm network with no persistent storage.

Endpoints:
  GET  /health      — liveness check
  POST /api/command — run a shell command, return stdout/stderr/timed_out
"""
import os
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)  # NOSONAR — no CSRF needed: stateless JSON API with no cookies/sessions, bound to localhost via Docker

# Optional shared secret — if MSF_API_SECRET is set, all /api/command
# requests must include it in the X-API-Secret header.
_API_SECRET = os.environ.get("MSF_API_SECRET", "")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/command", methods=["POST"])
def run_command():
    if _API_SECRET and request.headers.get("X-API-Secret") != _API_SECRET:
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json(force=True)
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
