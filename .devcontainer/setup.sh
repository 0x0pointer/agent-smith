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
# Only the tools are containerized. Use whatever your repo already defines.
if [ -f ./install.sh ]; then
  DEBIAN_FRONTEND=noninteractive bash ./install.sh     # repo's own tool-image build + MCP wiring
elif [ -f docker-compose.yml ] || [ -f compose.yaml ]; then
  docker compose pull || true
  docker compose build
else
  echo "No install.sh or compose file — add your tool-image build/pull here, e.g.:"
  # docker build -t agent-smith-tools:local ./tools
fi

# IMPORTANT: run the tools container on the HOST network so it shares the
# Codespace's tailnet interface — required to reach the lab AND to receive callbacks:
#   docker run --network=host … agent-smith-tools:local
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
