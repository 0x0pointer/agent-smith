#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# agent-smith Codespace setup
#   Harness runs NATIVELY (agent-smith, MCP server, Claude Code, opencode) — same as local.
#   Only the hacking tools run in a container (docker-in-docker).
#   Tailscale joins the Codespace to your lab so tools can reach targets AND get callbacks.
# ─────────────────────────────────────────────────────────────────────────────

# ── Repo root (this script lives in .devcontainer/) ──────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Skills submodule ─────────────────────────────────────────────────────────
# Codespaces doesn't always init submodules; the skill files live in the skills/
# submodule (https), so ensure it's checked out before installing skills below.
if [ -f "$REPO_ROOT/.gitmodules" ]; then
  git -C "$REPO_ROOT" submodule update --init --recursive --remote skills 2>/dev/null \
    || git -C "$REPO_ROOT" submodule update --init --recursive skills 2>/dev/null \
    || echo "WARN: could not init the skills submodule — skills will be missing."
fi

# ── Harness CLIs (native) ────────────────────────────────────────────────────
curl -fsSL https://claude.ai/install.sh | bash        # Claude Code (linux-x64)
npm install -g opencode-ai                             # opencode (x64 native binary)

# Poetry — the project's dependency manager. installers/run-mcp-server.sh resolves
# it from ~/.local/bin/poetry and runs the MCP server out of the Poetry venv, so it
# is REQUIRED for the native harness (there is no requirements.txt; deps live in
# pyproject.toml). The official installer drops it in ~/.local/bin.
if ! command -v poetry >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/poetry" ]; then
  echo "Installing Poetry…"
  curl -sSL https://install.python-poetry.org | python3 -
fi

grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc \
  || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"

# ── Native harness: Python deps + MCP SSE server ─────────────────────────────
# The harness runs natively (not in a container). This mirrors installers/install.sh
# MINUS the macOS launchd plist: installers/start-mcp-server.sh already falls back to
# a self-managed nohup instance on Linux (it guards `command -v launchctl`), so no
# plist / launchctl is involved here. Best-effort — warn, don't abort the Codespace.
echo "Installing Python dependencies (poetry install)…"
poetry -C "$REPO_ROOT" install --no-interaction \
  || echo "WARN: 'poetry install' failed — MCP server won't start until deps install."

echo "Starting MCP SSE server on localhost:7778…"
chmod +x "$REPO_ROOT/installers/start-mcp-server.sh"
"$REPO_ROOT/installers/start-mcp-server.sh" restart \
  || echo "WARN: MCP server failed to start — start later: installers/start-mcp-server.sh restart"

# Register the MCP server with Claude Code (SSE transport).
if command -v claude >/dev/null 2>&1; then
  claude mcp remove --scope user pentest-agent 2>/dev/null || true
  if claude mcp add --scope user --transport sse pentest-agent http://127.0.0.1:7778/sse; then
    echo "MCP server registered with Claude Code."
  else
    echo "WARN: 'claude mcp add' failed — register manually: claude mcp add --scope user --transport sse pentest-agent http://127.0.0.1:7778/sse"
  fi
fi

# ── opencode client assets (config + skills + plugin) ────────────────────────
# The Codespace also ships the opencode CLI, so wire it up the way
# installers/install_opencode.sh does — MINUS the image build / MCP start /
# supervisor (setup.sh already did those). The Codespace runs CLOUD Claude, so
# the installer's LOCAL-model context-window tuning does not apply; we set only
# the model-independent keys it sets (MCP entry, permissions, steps, compaction,
# CLAUDE.md instruction). opencode reads agent-callable skills from
# ~/.config/opencode/skills/<name>/SKILL.md and human /slash commands from
# ~/.config/opencode/commands/<name>.md — both get populated. It also uses the
# pentester-opencode client variant (which the Claude install above skips).
OPENCODE_CONFIG_DIR="$HOME/.config/opencode"
OPENCODE_CONFIG="$OPENCODE_CONFIG_DIR/opencode.json"
mkdir -p "$OPENCODE_CONFIG_DIR/commands" "$OPENCODE_CONFIG_DIR/skills" "$OPENCODE_CONFIG_DIR/plugins"

# Compaction-recovery plugin (preserves scan state across context compaction).
cp -f "$REPO_ROOT/installers/opencode-pentest-recovery.mjs" \
      "$OPENCODE_CONFIG_DIR/plugins/opencode-pentest-recovery.mjs" 2>/dev/null || true

# /pentester — prefer the opencode-specific variant, fall back to skills/pentester.md.
_oc_pentester=""
[ -f "$REPO_ROOT/skills/pentester-opencode/SKILL.md" ] && _oc_pentester="$REPO_ROOT/skills/pentester-opencode/SKILL.md"
[ -z "$_oc_pentester" ] && [ -f "$REPO_ROOT/skills/pentester.md" ] && _oc_pentester="$REPO_ROOT/skills/pentester.md"
if [ -n "$_oc_pentester" ]; then
  cp -f "$_oc_pentester" "$OPENCODE_CONFIG_DIR/commands/pentester.md"
  mkdir -p "$OPENCODE_CONFIG_DIR/skills/pentester"
  cp -f "$_oc_pentester" "$OPENCODE_CONFIG_DIR/skills/pentester/SKILL.md"
fi

# Every other skill → flat command (.md) + agent-skill folder (SKILL.md + refs).
_oc_cmd=0; _oc_skill=0
while IFS= read -r _skill_file; do
  [ -e "$_skill_file" ] || continue
  _skill_dir="$(dirname "$_skill_file")"
  _skill_name="$(basename "$_skill_dir")"
  [ "$_skill_name" = "pentester-opencode" ] && continue
  cp -f "$_skill_file" "$OPENCODE_CONFIG_DIR/commands/$_skill_name.md" 2>/dev/null && _oc_cmd=$((_oc_cmd + 1))
  rm -rf "$OPENCODE_CONFIG_DIR/skills/$_skill_name"
  mkdir -p "$OPENCODE_CONFIG_DIR/skills/$_skill_name"
  cp -R "$_skill_dir"/. "$OPENCODE_CONFIG_DIR/skills/$_skill_name"/ 2>/dev/null && _oc_skill=$((_oc_skill + 1))
done < <(find "$REPO_ROOT/skills" -mindepth 2 -maxdepth 3 -name SKILL.md 2>/dev/null)
echo "  opencode: $_oc_cmd slash commands + $_oc_skill agent skills installed"

# MCP server + permissions + CLAUDE.md instruction in opencode.json (created if
# missing). Model-independent subset of installers/install_opencode.sh — no local
# provider here, so its context-window detection is intentionally omitted.
OPENCODE_CONFIG="$OPENCODE_CONFIG" REPO_DIR="$REPO_ROOT" python3 - <<'PYEOF' || echo "WARN: opencode config write failed — register manually per installers/install_opencode.sh"
import json, os
from pathlib import Path
p = Path(os.environ["OPENCODE_CONFIG"]); repo = Path(os.environ["REPO_DIR"])
try:
    data = json.loads(p.read_text()) if p.exists() else {}
except Exception:
    data = {}
# opencode's schema uses "remote" for any HTTP/SSE MCP server (no "sse" type).
# 2.5h timeout keeps long tools (spider/sqlmap/kali) from tripping opencode's 5s default.
data.setdefault("mcp", {})["pentest-agent"] = {
    "type": "remote", "url": "http://127.0.0.1:7778/sse", "enabled": True, "timeout": 9_000_000,
}
perm = data.setdefault("permission", {})
perm["doom_loop"] = "allow"                      # pentest fuzzing is legitimate repeated tool use
for k in ("bash", "edit", "webfetch", "external_directory"):
    perm.setdefault(k, "allow")
data.setdefault("agent", {}).setdefault("build", {}).setdefault("steps", 10000)
comp = data.setdefault("compaction", {}); comp["auto"] = True; comp.setdefault("prune", True)
comp["reserved"] = max(comp.get("reserved", 0), 16000)   # cloud-model fallback (beats opencode's 10k default)
instr = data.setdefault("instructions", [])
entry = str(repo / "CLAUDE.md")
if entry not in instr:
    instr.append(entry)
p.write_text(json.dumps(data, indent=2) + "\n")
print(f"  opencode: MCP server + CLAUDE.md registered in {p}")
PYEOF

# ── Security-analysis skills (Claude Code) ───────────────────────────────────
# Mirror installers/install.sh: install the /pentester slash command, then every
# skill folder into ~/.claude/skills/<leaf-name>/ (flat), discovered from both
# skills/<name>/SKILL.md and skills/<domain>/<name>/SKILL.md. Fresh env → overwrite.
echo "Installing security-analysis skills into ~/.claude…"
mkdir -p "$HOME/.claude/commands" "$HOME/.claude/skills"
if [ -f "$REPO_ROOT/skills/pentester.md" ]; then
  cp -f "$REPO_ROOT/skills/pentester.md" "$HOME/.claude/commands/pentester.md"
fi
_skill_count=0
while IFS= read -r _skill_file; do
  [ -e "$_skill_file" ] || continue
  _skill_dir="$(dirname "$_skill_file")"
  _skill_name="$(basename "$_skill_dir")"
  # opencode has a client-specific variant; Claude uses skills/pentester.md.
  [ "$_skill_name" = "pentester-opencode" ] && continue
  rm -rf "$HOME/.claude/skills/$_skill_name"
  mkdir -p "$HOME/.claude/skills/$_skill_name"
  if cp -R "$_skill_dir"/. "$HOME/.claude/skills/$_skill_name"/ 2>/dev/null; then
    _skill_count=$((_skill_count + 1))
  else
    echo "  WARN: failed to install skill /$_skill_name"
  fi
done < <(find "$REPO_ROOT/skills" -mindepth 2 -maxdepth 3 -name SKILL.md 2>/dev/null)
echo "  installed $_skill_count skills + /pentester command"

# ── Docker daemon (for the hacking-tools container only) ─────────────────────
echo "Waiting for the Docker daemon…"
timeout 60 bash -c 'until docker info >/dev/null 2>&1; do sleep 2; done' \
  || { echo "ERROR: Docker daemon did not become ready"; exit 1; }

# ── Hacking-tools container: build & pull ────────────────────────────────────
# Only the tools are containerized (the harness runs natively — see above), so this
# step builds the tool IMAGES only, using the repo's real recipe (same builds
# installers/install.sh bakes in; tags pentest-agent/kali-mcp + pentest-agent/
# metasploit, per tools/*_runner.py). A compose file, if ever added, takes precedence.
if [ -f "$REPO_ROOT/docker-compose.yml" ] || [ -f "$REPO_ROOT/compose.yaml" ] || [ -f "$REPO_ROOT/compose.yml" ]; then
  ( cd "$REPO_ROOT" && { docker compose pull || true; } && docker compose build )
else
  # Kali image — the Codespace bakes in EVERY module (web + infra + mobile + cloud
  # + ai), not just the web+infra defaults, so all skills work out of the box. This
  # is a heavy build (the ai module pulls torch — expect a long first create).
  # Best-effort: warn, don't abort the Codespace.
  _KALI_ARGS=(
    --build-arg INSTALL_WEB=1
    --build-arg INSTALL_INFRA=1
    --build-arg INSTALL_MOBILE=1
    --build-arg INSTALL_CLOUD=1
    --build-arg INSTALL_AI=1
  )
  echo "Building pentest-agent/kali-mcp (tools/kali) with ALL modules — this takes a while…"
  docker build "${_KALI_ARGS[@]}" -t pentest-agent/kali-mcp "$REPO_ROOT/tools/kali/" \
    || echo "WARN: kali-mcp build failed — rebuild later: docker build ${_KALI_ARGS[*]} -t pentest-agent/kali-mcp $REPO_ROOT/tools/kali/"
  # Metasploit image — heavier, only needed for the /metasploit skill. Best-effort.
  echo "Building pentest-agent/metasploit (tools/metasploit)…"
  docker build -t pentest-agent/metasploit "$REPO_ROOT/tools/metasploit/" \
    || echo "WARN: metasploit build failed — rebuild later: docker build -t pentest-agent/metasploit $REPO_ROOT/tools/metasploit/"
  # Scanner images (recon: nmap/naabu/httpx/nuclei/subfinder + fuzzyai) are pulled
  # in the step below. ffuf/spider/garak/promptfoo run INSIDE the Kali image built
  # above — they are not separate images.
fi

# ── Pre-pull scanner images ──────────────────────────────────────────────────
# Parity with installers/install.sh (which pre-pulls these). Enumerate the exact
# refs from the tool REGISTRY — the same set the `pull_images` action fetches, and
# digest-pinned — so this never drifts from a hardcoded tag list. Best-effort: any
# image not pulled here still auto-pulls on first `docker run`. The needs_mount
# tools (semgrep/trufflehog/mobsfscan) auto-pull when a codebase/target is first
# mounted, matching pull_images, so they are intentionally not fetched here.
if command -v poetry >/dev/null 2>&1; then
  echo "Pre-pulling scanner images (from the tool registry)…"
  _imgs="$( ( cd "$REPO_ROOT" && poetry run python -c 'from tools import REGISTRY; print("\n".join(sorted({t.image for t in REGISTRY.values() if not getattr(t,"needs_mount",False) and getattr(t,"image","")})))' ) 2>/dev/null || true )"
  for _img in $_imgs; do
    if docker pull "$_img" >/dev/null 2>&1; then
      echo "  pulled $_img"
    else
      echo "  WARN: pull failed (auto-pulls on first use): $_img"
    fi
  done
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
