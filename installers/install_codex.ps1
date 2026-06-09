<#
.SYNOPSIS
    pentest-agent installer for Codex (Windows / PowerShell port of install_codex.sh)

.DESCRIPTION
    Registers the pentest-agent MCP server with OpenAI Codex over stdio
    transport (Codex spawns the MCP server as a subprocess, so no SSE port
    is needed). Also installs Codex skills into ~/.codex/skills.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$RepoDir       = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CodexHome     = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
$CodexSkills   = Join-Path $CodexHome 'skills'

function Write-Ok    { param([string]$m) Write-Host "OK   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "WARN $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "FAIL $m" -ForegroundColor Red; exit 1 }
function Test-Cmd    { param([string]$name) [bool](Get-Command $name -ErrorAction SilentlyContinue) }

Write-Host ''
Write-Host '  pentest-agent installer (Codex / Windows)'
Write-Host '  ========================================='
Write-Host ''

if (-not (Test-Cmd docker)) { Write-Fail 'docker not found — install Docker Desktop.' }
if (-not (Test-Cmd poetry)) { Write-Fail 'poetry not found — install via: pipx install poetry' }
if (-not (Test-Cmd codex))  { Write-Fail 'codex not found — install Codex first: https://developers.openai.com/codex' }
Write-Ok 'Prerequisites satisfied (docker, poetry, codex)'

New-Item -ItemType Directory -Path $CodexHome -Force | Out-Null

Write-Host ''
Write-Host 'Updating skills submodule...'
try {
    Push-Location $RepoDir
    git submodule update --init --recursive --remote skills | Out-Null
    if ($LASTEXITCODE -ne 0) {
        git submodule update --init --recursive skills | Out-Null
    }
    $sha = git -C (Join-Path $RepoDir 'skills') rev-parse --short HEAD
    Write-Ok "Skills submodule at $sha"
} finally { Pop-Location }

Write-Host ''
Write-Host 'Installing Python dependencies...'
poetry -C $RepoDir install --no-interaction
if ($LASTEXITCODE -ne 0) { Write-Fail 'poetry install failed' }
Write-Ok 'Poetry dependencies installed'

# ── Register MCP with Codex (stdio) ──────────────────────────────────────────
Write-Host ''
Write-Host 'Registering pentest-agent MCP server with Codex (stdio)...'
codex mcp remove pentest-agent 2>$null | Out-Null
codex mcp add pentest-agent -- poetry -C $RepoDir run python -m mcp_server
Write-Ok 'MCP server registered with Codex'

# ── Skills ───────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $CodexSkills -Force | Out-Null
$pentesterDst = Join-Path $CodexSkills 'pentester'
New-Item -ItemType Directory -Path $pentesterDst -Force | Out-Null
Copy-Item -Path (Join-Path $RepoDir 'skills\pentester.md') `
          -Destination (Join-Path $pentesterDst 'SKILL.md') -Force

$installed = 0
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Directory | ForEach-Object {
    $name = $_.Name
    if ($name -eq 'pentester-opencode') { return }
    $src = Join-Path $_.FullName 'SKILL.md'
    if (-not (Test-Path $src)) { return }
    $dst = Join-Path $CodexSkills $name
    if (Test-Path $dst) { Remove-Item -Path $dst -Recurse -Force }
    Copy-Item -Path $_.FullName -Destination $dst -Recurse -Force
    $installed++
}
Write-Ok "$installed Codex skills installed"

Write-Host ''
Write-Host '  Install complete!'
Write-Host '  Codex will spawn the MCP server over stdio on first /pentester invocation.'
Write-Host '  (No Task Scheduler entry needed — Codex manages the MCP lifecycle itself.)'
Write-Host ''
