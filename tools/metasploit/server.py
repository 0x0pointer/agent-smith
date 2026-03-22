#!/usr/bin/env python3
"""
Thin Flask API for the Metasploit container.
Mirrors the kali-server-mcp interface so metasploit_runner.py works
with the same HTTP pattern.

Endpoints:
  GET  /health      — liveness check
  POST /api/command — run a shell command, return stdout/stderr/timed_out
"""
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/command", methods=["POST"])
def run_command():
    data = request.get_json(force=True)
    command = data.get("command", "")
    timeout = data.get("timeout", 900)

    try:
        result = subprocess.run(
            command,
            shell=True,
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
    app.run(host="0.0.0.0", port=5000)
