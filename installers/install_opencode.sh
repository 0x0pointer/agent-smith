#!/usr/bin/env bash
# install_opencode.sh — set up pentest-agent for opencode
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCODE_CONFIG_DIR="$HOME/.config/opencode"
OPENCODE_CONFIG="$OPENCODE_CONFIG_DIR/opencode.json"
OPENCODE_COMMANDS_DIR="$OPENCODE_CONFIG_DIR/commands"

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

# ── Install slash commands ────────────────────────────────────────────────────
echo ""
echo "Installing slash commands..."
mkdir -p "$OPENCODE_COMMANDS_DIR"
cp "$REPO_DIR/skills/pentester.md"                "$OPENCODE_COMMANDS_DIR/pentester.md"
cp "$REPO_DIR/skills/analyze-cve/SKILL.md"       "$OPENCODE_COMMANDS_DIR/analyze-cve.md"
cp "$REPO_DIR/skills/threat-modeling/SKILL.md"   "$OPENCODE_COMMANDS_DIR/threat-model.md"
cp "$REPO_DIR/skills/aikido-triage/SKILL.md"     "$OPENCODE_COMMANDS_DIR/aikido-triage.md"
cp "$REPO_DIR/skills/gh-export/SKILL.md"         "$OPENCODE_COMMANDS_DIR/gh-export.md"
cp "$REPO_DIR/skills/ai-redteam/SKILL.md"       "$OPENCODE_COMMANDS_DIR/ai-redteam.md"
ok "/pentester, /analyze-cve, /threat-model, /aikido-triage, /gh-export, /ai-redteam commands available in all opencode sessions"

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
echo "  Available commands:"
echo "    /pentester scan https://target.com       — full pentest"
echo "    /analyze-cve lodash 4.17.20 CVE-...      — CVE exploitability analysis"
echo "    /threat-model                             — PASTA threat model"
echo "    /aikido-triage findings.csv /path/to/app — triage Aikido CSV + HTML report"
echo "    /gh-export                               — export findings as GitHub issue blocks"
echo ""
