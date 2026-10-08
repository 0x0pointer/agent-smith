#!/usr/bin/env python3
"""
Loopback auth guard for the Kali API.

kali-server-mcp exposes an UNAUTHENTICATED ``POST /api/command`` that runs arbitrary
shell as root, and has no token/Host checks of its own. This guard sits in front of it:

  * binds the Docker-published port (default 0.0.0.0:5000 inside the container),
  * enforces a shared-secret token (``KALI_API_TOKEN``) on every request — so a local
    process or a DNS-rebinding page that reaches loopback still can't drive it,
  * enforces a Host allowlist (localhost / 127.0.0.1) — which specifically defeats DNS
    rebinding (the rebound request carries ``Host: attacker.example``),
  * forwards allowed requests to the real server on 127.0.0.1:``KALI_UPSTREAM_PORT``.

Combined with a loopback-only Docker publish (``-p 127.0.0.1:5001:5000``) this closes the
network, rebinding, and local-process vectors. Stdlib-only (no pip deps in the image).
If ``KALI_API_TOKEN`` is empty the guard runs OPEN and logs a warning (back-compat).

``POST /api/command`` is executed HERE rather than forwarded: upstream kali-server-mcp
ignores the request's ``timeout`` field and kills every command at a hard-coded 180 s,
so a ``kali(command, timeout=900)`` batch job was silently cut off at ~3 min. The guard
runs the command itself honouring ``timeout`` (clamped to [1, MAX_COMMAND_TIMEOUT]) and
returns the same JSON shape upstream does. Every other route is still proxied.
"""
import http.server
import json
import os
import signal
import subprocess
import urllib.error
import urllib.request

TOKEN = os.environ.get("KALI_API_TOKEN", "").strip()
UPSTREAM = f"http://127.0.0.1:{os.environ.get('KALI_UPSTREAM_PORT', '5555')}"
GUARD_PORT = int(os.environ.get("KALI_GUARD_PORT", "5000"))
# Only these Host header hostnames may reach the API. A DNS-rebinding page's request
# arrives with the attacker's domain in Host, so it is rejected here.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "kali", "pentest-kali"}
_FORWARD_TIMEOUT = None  # long tools (nmap/gobuster) hold the connection; upstream owns the tool timeout
DEFAULT_COMMAND_TIMEOUT = 180
MAX_COMMAND_TIMEOUT = int(os.environ.get("KALI_MAX_COMMAND_TIMEOUT", "7200"))


def _clamp_timeout(raw) -> int:
    try:
        t = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_COMMAND_TIMEOUT
    return max(1, min(t, MAX_COMMAND_TIMEOUT))


def run_command(command: str, timeout) -> dict:
    """Run ``command`` via /bin/sh honouring ``timeout``; on expiry kill the whole
    process group (so a backgrounded child can't hold the pipes open) and return the
    partial output. Mirrors kali-server-mcp's response shape."""
    timeout = _clamp_timeout(timeout)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,  # noqa: S602 — this IS the command API
                            stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                break
            try:
                proc.wait(timeout=5)
                break
            except subprocess.TimeoutExpired:
                continue
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = b"", b""
    stdout = (out or b"").decode("utf-8", "replace")
    stderr = (err or b"").decode("utf-8", "replace")
    rc = -1 if timed_out else proc.returncode
    return {"stdout": stdout, "stderr": stderr, "return_code": rc,
            "success": bool(stdout or stderr) if timed_out else rc == 0,
            "timed_out": timed_out, "timeout": timeout,
            "partial_results": timed_out and bool(stdout or stderr)}


class Guard(http.server.BaseHTTPRequestHandler):
    def _host_ok(self) -> bool:
        return (self.headers.get("Host", "").split(":")[0].strip().lower()) in ALLOWED_HOSTS

    def _token_ok(self) -> bool:
        if not TOKEN:
            return True
        got = self.headers.get("X-Kali-Token", "") or \
            self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        # constant-time-ish compare
        return len(got) == len(TOKEN) and all(a == b for a, b in zip(got, TOKEN))

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _proxy(self) -> None:
        if not self._host_ok():
            return self._send(421, b'{"error":"forbidden host"}')
        if not self._token_ok():
            return self._send(401, b'{"error":"unauthorized"}')
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        if self.command == "POST" and self.path.split("?")[0] == "/api/command":
            return self._command(body)
        req = urllib.request.Request(UPSTREAM + self.path, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "x-kali-token", "authorization"):
                req.add_header(k, v)
        if body is not None:
            req.add_header("Content-Length", str(len(body)))
        try:
            with urllib.request.urlopen(req, timeout=_FORWARD_TIMEOUT) as r:
                data = r.read()
                self._send(r.status, data, r.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as e:
            data = e.read()
            self._send(e.code, data, e.headers.get("Content-Type", "application/json"))
        except Exception:
            self._send(502, b'{"error":"upstream unreachable"}')

    def _command(self, body) -> None:
        try:
            params = json.loads(body or b"{}")
        except ValueError:
            return self._send(400, b'{"error":"invalid JSON"}')
        command = (params or {}).get("command", "")
        if not command:
            return self._send(400, b'{"error":"Command parameter is required"}')
        self._send(200, json.dumps(run_command(command, params.get("timeout"))).encode())

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _proxy

    def log_message(self, *_a):  # silence per-request stderr noise
        pass


if __name__ == "__main__":
    if not TOKEN:
        print("WARN: KALI_API_TOKEN unset — Kali API guard running WITHOUT token auth", flush=True)
    print(f"kali-api-guard: :{GUARD_PORT} -> {UPSTREAM} (token={'on' if TOKEN else 'OFF'}, "
          f"hosts={sorted(ALLOWED_HOSTS)})", flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", GUARD_PORT), Guard).serve_forever()
