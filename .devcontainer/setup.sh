#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# agent-smith Codespace setup
#   Harness runs NATIVELY (agent-smith, MCP server, Claude Code, opencode) — same as local.
#   Only the hacking tools run in a container (docker-in-docker).
#   Tailscale joins the Codespace to your lab so tools can reach targets AND get callbacks.
# ─────────────────────────────────────────────────────────────────────────────

# ── Harness CLIs (native) ────────────────────────────────────────────────────
curl -fsSL https://claude.ai/install.sh | bash        # Claude Code (linux-x64)
npm install -g opencode-ai                             # opencode (x64 native binary)
[ -f requirements.txt ] && pip install --user -r requirements.txt

grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc \
  || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"

# ── Docker daemon (for the hacking-tools container only) ─────────────────────
echo "Waiting for the Docker daemon…"
timeout 60 bash -c 'until docker info >/dev/null 2>&1; do sleep 2; done' \
  || { echo "ERROR: Docker daemon did not become ready"; exit 1; }

# ── Hacking-tools container: build & pull ────────────────────────────────────
# Only the tools are containerized (the harness runs natively — see top of file),
# so this step builds the tool IMAGES only. The repo's real image mechanism is the
# docker builds below — the same recipe installers/install.sh bakes in (tags
# pentest-agent/kali-mcp + pentest-agent/metasploit, per tools/*_runner.py).
#
# We deliberately do NOT run installers/install.sh here: it is the macOS/native
# full-harness installer (hard-requires poetry, runs `poetry install`, writes a
# launchd plist and `launchctl load`) and would abort on this Linux Codespace.
# A compose file, if the repo ever adds one, takes precedence.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$REPO_ROOT/docker-compose.yml" ] || [ -f "$REPO_ROOT/compose.yaml" ] || [ -f "$REPO_ROOT/compose.yml" ]; then
  ( cd "$REPO_ROOT" && { docker compose pull || true; } && docker compose build )
else
  # Kali image (recon + web/infra tooling) — required for most skills. A plain build
  # uses the Dockerfile's default ARGs (INSTALL_WEB=1 INSTALL_INFRA=1), matching the
  # installer's interactive defaults. Best-effort: warn, don't abort the Codespace.
  echo "Building pentest-agent/kali-mcp (tools/kali) — this takes a while…"
  docker build -t pentest-agent/kali-mcp "$REPO_ROOT/tools/kali/" \
    || echo "WARN: kali-mcp build failed — rebuild later: docker build -t pentest-agent/kali-mcp $REPO_ROOT/tools/kali/"
  # Metasploit image — heavier, only needed for the /metasploit skill. Best-effort.
  echo "Building pentest-agent/metasploit (tools/metasploit)…"
  docker build -t pentest-agent/metasploit "$REPO_ROOT/tools/metasploit/" \
    || echo "WARN: metasploit build failed — rebuild later: docker build -t pentest-agent/metasploit $REPO_ROOT/tools/metasploit/"
  # Lightweight scanner images (nmap/naabu/httpx/nuclei/subfinder/ffuf/semgrep/
  # trufflehog) are public and auto-pull on first use — no build needed here.
fi

# IMPORTANT: run the tools container on the HOST network so it shares the
# Codespace's tailnet interface — required to reach the lab AND to receive callbacks:
#   docker run --network=host … pentest-agent/kali-mcp
# (compose: set  network_mode: host  on the tools service)
# Point reverse shells / handlers at the Codespace tailnet IP, not a public one.

# ── Tailscale status ─────────────────────────────────────────────────────────
if command -v tailscale >/dev/null 2>&1; then
  if tailscale status >/dev/null 2>&1; then
    echo "Tailscale up. Codespace tailnet IP: $(tailscale ip -4 2>/dev/null || true)"
    echo "  -> use this IP as the callback/LHOST for reverse shells."
  else
    echo "Tailscale installed but not up — set the TS_AUTH_KEY secret, or run:"
    echo "  sudo tailscale up --accept-routes"
  fi
fi

# ── Claude auth: API key -> OAuth token -> browser login ─────────────────────
if [ -n "${ANTHROPIC_API_KEY:-}" ] && [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  echo "WARN: both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN set — unset one (Claude warns on the conflict)."
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo "Claude: ANTHROPIC_API_KEY present (API billing)."
elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  echo "Claude: CLAUDE_CODE_OAUTH_TOKEN present (subscription)."
else
  echo "Claude: no credential → run 'claude' in the VS Code terminal and use /login."
fi

echo "Setup complete."
