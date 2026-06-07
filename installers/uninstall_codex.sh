#!/usr/bin/env bash
# uninstall_codex.sh - remove pentest-agent from OpenAI Codex
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CODEX_SKILLS_DIR="$CODEX_HOME/skills"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

echo ""
echo "  pentest-agent uninstaller (Codex)"
echo "  ================================="
echo ""

# Remove the Codex MCP registration. This only changes Codex's MCP config; it
# does not remove the repo, .env, logs, Docker images, or Poetry virtualenv.
if command -v codex >/dev/null 2>&1; then
    codex mcp remove pentest-agent >/dev/null 2>&1 \
        && ok "pentest-agent MCP server removed from Codex" \
        || warn "pentest-agent MCP server was not registered with Codex (skipping)"
else
    warn "codex CLI not found - skipping MCP removal"
fi

if [ ! -d "$CODEX_SKILLS_DIR" ]; then
    warn "$CODEX_SKILLS_DIR not found - skipping skill removal"
    echo ""
    echo "  Uninstall complete."
    exit 0
fi

_TMP_SKILLS="$(mktemp)"
trap 'rm -f "$_TMP_SKILLS"' EXIT

# Fallback list covers Smith skills installed by older installers even when the
# current skills submodule is incomplete or has local edits.
cat > "$_TMP_SKILLS" <<'EOF'
ad-assessment
ai-redteam
aikido-triage
analyze-cve
api-security
business-logic
cloud-security
codebase
colang-gen
compliance
container-k8s-security
credential-audit
email-security
gh-export
lateral-movement
metasploit
network-assess
oauth-security
osint
param-fuzz
pentester
post-exploit
remediate
report
request-cves
reverse-shell
ssl-tls-audit
threat-modeling
web-exploit
EOF

# Also include any current repo skill directories so newly added Smith skills do
# not require a matching uninstaller patch.
if [ -d "$REPO_DIR/skills" ]; then
    for _skill_file in "$REPO_DIR"/skills/*/SKILL.md; do
        [ -e "$_skill_file" ] || continue
        _skill_name="$(basename "$(dirname "$_skill_file")")"
        [ "$_skill_name" = "pentester-opencode" ] && continue
        printf '%s\n' "$_skill_name" >> "$_TMP_SKILLS"
    done
fi

_REMOVED=0
_SKIPPED=0
while IFS= read -r _skill_name; do
    [ -n "$_skill_name" ] || continue
    _skill_dir="$CODEX_SKILLS_DIR/$_skill_name"
    if [ -d "$_skill_dir" ]; then
        rm -rf "$_skill_dir"
        ok "Removed Codex skill: $_skill_name"
        _REMOVED=$((_REMOVED + 1))
    else
        _SKIPPED=$((_SKIPPED + 1))
    fi
done < <(sort -u "$_TMP_SKILLS")

echo ""
ok "Removed $_REMOVED Codex skill directories"
if [ "$_SKIPPED" -gt 0 ]; then
    warn "$_SKIPPED Smith skill directories were not installed (skipped)"
fi

echo ""
echo "  Uninstall complete."
echo "  Note: Docker images, containers, .env, logs, and the Poetry virtualenv were NOT removed."
echo "  To clean Docker artifacts manually:"
echo "    docker rm -f pentest-kali pentest-metasploit 2>/dev/null || true"
echo "    docker rmi pentest-agent/kali-mcp pentest-agent/metasploit 2>/dev/null || true"
echo ""
