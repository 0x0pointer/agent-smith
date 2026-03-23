#!/usr/bin/env bash
# install_opencode.sh — set up pentest-agent for opencode
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCODE_CONFIG_DIR="$HOME/.config/opencode"
OPENCODE_CONFIG="$OPENCODE_CONFIG_DIR/opencode.json"
OPENCODE_COMMANDS_DIR="$OPENCODE_CONFIG_DIR/commands"
OPENCODE_PLUGINS_DIR="$OPENCODE_CONFIG_DIR/plugins"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✗${NC} $*"; exit 1; }

echo ""
echo "  pentest-agent installer (opencode)"
echo "  ===================================="
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v docker   >/dev/null 2>&1 || die "docker not found — install Docker Desktop first."
command -v poetry   >/dev/null 2>&1 || die "poetry not found — install with: curl -sSL https://install.python-poetry.org | python3 -"
command -v opencode >/dev/null 2>&1 || die "opencode not found — install from: https://opencode.ai"

ok "Prerequisites satisfied (docker, poetry, opencode)"

# ── Pull skills submodule ────────────────────────────────────────────────────
echo ""
echo "Pulling skills submodule..."
git -C "$REPO_DIR" submodule update --init --recursive
ok "Skills submodule up to date"

# ── Python dependencies ───────────────────────────────────────────────────────
echo ""
echo "Installing Python dependencies..."
poetry -C "$REPO_DIR" install --no-interaction
ok "Poetry dependencies installed"

# ── Register MCP server + instructions in opencode config ────────────────────
echo ""
echo "Registering pentest-agent MCP server in opencode config..."
mkdir -p "$OPENCODE_CONFIG_DIR"

python3 - <<PYEOF
import json
from pathlib import Path

config_path = Path("$OPENCODE_CONFIG")
repo_dir    = Path("$REPO_DIR")

try:
    data = json.loads(config_path.read_text()) if config_path.exists() else {}
except Exception:
    data = {}

# MCP server entry
mcp = data.setdefault("mcp", {})
mcp["pentest-agent"] = {
    "type":    "local",
    "command": ["poetry", "-C", str(repo_dir), "run", "python", "mcp_server.py"],
    "enabled": True,
    "timeout": 30000,
}

# Add CLAUDE.md to global instructions (avoid duplicates)
instructions = data.setdefault("instructions", [])
instructions_entry = str(repo_dir / "CLAUDE.md")
if instructions_entry not in instructions:
    instructions.append(instructions_entry)

config_path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF
ok "MCP server registered in $OPENCODE_CONFIG"
ok "CLAUDE.md added to global instructions"

# ── Install compaction recovery plugin ──────────────────────────────────────
echo ""
echo "Installing compaction recovery plugin..."
mkdir -p "$OPENCODE_PLUGINS_DIR"
cp "$REPO_DIR/installers/opencode-pentest-recovery.mjs" \
   "$OPENCODE_PLUGINS_DIR/opencode-pentest-recovery.mjs"
ok "Compaction recovery plugin installed (preserves scan state across context compaction)"

# ── Install slash commands ────────────────────────────────────────────────────
echo ""
echo "Installing slash commands..."
mkdir -p "$OPENCODE_COMMANDS_DIR"

# /pentester — top-level command
cp "$REPO_DIR/skills/pentester.md" "$OPENCODE_COMMANDS_DIR/pentester.md"
ok "/pentester command installed"

# Skill commands — each gets its own file
_install_skill() {
    local name="$1"
    local src="$2"
    cp "$src" "$OPENCODE_COMMANDS_DIR/${name}.md"
}

_install_skill "analyze-cve"            "$REPO_DIR/skills/analyze-cve/SKILL.md"
_install_skill "threat-model"           "$REPO_DIR/skills/threat-modeling/SKILL.md"
_install_skill "aikido-triage"          "$REPO_DIR/skills/aikido-triage/SKILL.md"
_install_skill "gh-export"              "$REPO_DIR/skills/gh-export/SKILL.md"
_install_skill "ai-redteam"            "$REPO_DIR/skills/ai-redteam/SKILL.md"
_install_skill "container-k8s-security" "$REPO_DIR/skills/container-k8s-security/SKILL.md"
_install_skill "cloud-security"         "$REPO_DIR/skills/cloud-security/SKILL.md"
_install_skill "ad-assessment"          "$REPO_DIR/skills/ad-assessment/SKILL.md"
_install_skill "email-security"         "$REPO_DIR/skills/email-security/SKILL.md"
_install_skill "metasploit"             "$REPO_DIR/skills/metasploit/SKILL.md"
_install_skill "reverse-shell"          "$REPO_DIR/skills/reverse-shell/SKILL.md"
_install_skill "web-exploit"            "$REPO_DIR/skills/web-exploit/SKILL.md"
_install_skill "codebase"               "$REPO_DIR/skills/codebase/SKILL.md"
_install_skill "remediate"              "$REPO_DIR/skills/remediate/SKILL.md"
_install_skill "credential-audit"       "$REPO_DIR/skills/credential-audit/SKILL.md"
_install_skill "lateral-movement"       "$REPO_DIR/skills/lateral-movement/SKILL.md"
_install_skill "network-assess"         "$REPO_DIR/skills/network-assess/SKILL.md"
_install_skill "osint"                  "$REPO_DIR/skills/osint/SKILL.md"
_install_skill "post-exploit"           "$REPO_DIR/skills/post-exploit/SKILL.md"
_install_skill "ssl-tls-audit"          "$REPO_DIR/skills/ssl-tls-audit/SKILL.md"
ok "20 skill commands installed"

# ── Install web-exploit reference files (lazy-loaded per injection type) ─────
echo ""
echo "Installing web-exploit reference files..."
REFS_SRC="$REPO_DIR/skills/web-exploit/refs"
REFS_DST="$OPENCODE_COMMANDS_DIR/web-exploit-refs"
if [ -d "$REFS_SRC" ]; then
    mkdir -p "$REFS_DST"
    cp "$REFS_SRC"/*.md "$REFS_DST/"
    REF_COUNT=$(ls "$REFS_DST"/*.md 2>/dev/null | wc -l | tr -d ' ')
    ok "$REF_COUNT injection reference files installed (lazy-loaded to save context)"
else
    warn "web-exploit/refs/ not found — refs will be read from repo at runtime"
fi

# ── Next steps ────────────────────────────────────────────────────────────────
echo ""
echo "  Done! Optional next steps:"
echo ""
echo "  1. Pre-pull lightweight tool images (recommended, ~2 min):"
echo "     Start opencode and ask it to: call the pull_images tool"
echo "     Or manually:"
echo "     docker pull instrumentisto/nmap projectdiscovery/naabu projectdiscovery/httpx \\"
echo "                projectdiscovery/nuclei ghcr.io/ffuf/ffuf projectdiscovery/subfinder \\"
echo "                semgrep/semgrep trufflesecurity/trufflehog"
echo ""
echo "  2. Build the Kali image (optional, ~10 min — required for kali_exec):"
echo "     docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo ""
echo "  3. Build the Metasploit image (optional, ~5 min — required for /metasploit):"
echo "     docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
echo ""
echo "  Available commands:"
echo "    /pentester scan https://target.com       — full pentest"
echo "    /analyze-cve lodash 4.17.20 CVE-...      — CVE exploitability analysis"
echo "    /threat-model                             — PASTA threat model"
echo "    /aikido-triage findings.csv /path/to/app — triage Aikido CSV + HTML report"
echo "    /ai-redteam https://ai-app.com/api/chat   — OWASP LLM Top 10 red-team assessment"
echo "    /cloud-security my-aws-account provider=aws — cloud security posture assessment"
echo "    /ad-assessment 10.0.0.1 domain=CORP.LOCAL  — Active Directory security audit"
echo "    /email-security example.com              — email SPF/DKIM/DMARC audit"
echo "    /metasploit 10.0.0.5 cve=CVE-2017-0144   — Metasploit exploit validation"
echo "    /gh-export                               — export findings as GitHub issue blocks"
echo ""
