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

# ── Docker images ────────────────────────────────────────────────────────────
#
# WSL2 prerequisite: Docker Desktop must use the WSL 2 based engine
# (Settings -> General). Hyper-V classic backend cannot build the Linux
# images Kali ships. `docker build` will fail loudly if the wrong backend
# is in use; we fall through to "build later" in that case.
Write-Host ''
Write-Host '  Docker images'
Write-Host '  -------------'
Write-Host ''

function Confirm-Yes {
    param([string]$Prompt)
    $ans = Read-Host "$Prompt [Y/n]"
    return ($ans -eq '' -or $ans -match '^[Yy]')
}

function Confirm-Default {
    param([string]$Prompt, [bool]$Default = $true)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $ans = Read-Host "$Prompt $hint"
    if ($ans -eq '') { return $Default }
    return ($ans -match '^[Yy]')
}

$ScannerImages = @(
    'instrumentisto/nmap'
    'projectdiscovery/naabu'
    'projectdiscovery/httpx'
    'projectdiscovery/nuclei'
    'projectdiscovery/subfinder'
    'semgrep/semgrep'
    'trufflesecurity/trufflehog'
)

if (Confirm-Yes '  Pull lightweight scanner images? (~2 min)') {
    foreach ($img in $ScannerImages) {
        docker pull $img 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Pulled $img"
        } else {
            Write-Warn "Failed to pull $img (will auto-pull on first use)"
        }
    }
} else {
    Write-Warn 'Scanner image pull skipped - images will auto-pull on first use'
}

Write-Host ''
$KaliCtx = Join-Path $RepoDir 'tools\kali\'
if (Confirm-Yes '  Build Kali image? (required for most skills)') {
    Write-Host ''
    Write-Host '  Choose Kali tool modules (core is always included). Build-time'
    Write-Host '  estimates are approximate and depend on your network speed:'
    Write-Host ''
    Write-Host '    core   (always)  MCP server, recon: nmap/nuclei/httpx/subfinder    ~6 min'
    Write-Host '    web              web/API exploit, fuzzing, injection, JWT, SSL      ~8 min'
    Write-Host '    infra            internal net, AD, credentials, service enum, pivot ~5 min'
    Write-Host '    mobile           Android/iOS reversing + Frida dynamic analysis     ~4 min'
    Write-Host '    cloud            AWS/Azure/GCP CLIs, Prowler, ScoutSuite, trivy      ~7 min'
    Write-Host '    ai               LLM red-team: PyRIT, Garak, promptfoo (heaviest)   ~12 min'
    Write-Host ''
    $kaliArgs = @()
    foreach ($m in @(
        @{ Name = 'web';    Arg = 'INSTALL_WEB';    Def = $true  },
        @{ Name = 'infra';  Arg = 'INSTALL_INFRA';  Def = $true  },
        @{ Name = 'mobile'; Arg = 'INSTALL_MOBILE'; Def = $false },
        @{ Name = 'cloud';  Arg = 'INSTALL_CLOUD';  Def = $false },
        @{ Name = 'ai';     Arg = 'INSTALL_AI';     Def = $false }
    )) {
        $val = if (Confirm-Default ("    Include {0} module?" -f $m.Name) $m.Def) { '1' } else { '0' }
        $kaliArgs += '--build-arg'; $kaliArgs += ('{0}={1}' -f $m.Arg, $val)
    }
    Write-Host '  Building pentest-agent/kali-mcp (this may take a while)...'
    docker build @kaliArgs -t pentest-agent/kali-mcp $KaliCtx
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Kali image built: pentest-agent/kali-mcp'
    } else {
        Write-Warn "Kali build failed - run manually: docker build -t pentest-agent/kali-mcp $KaliCtx"
    }
} else {
    Write-Warn "Kali build skipped - run later: docker build -t pentest-agent/kali-mcp $KaliCtx"
}

Write-Host ''
$MsfCtx = Join-Path $RepoDir 'tools\metasploit\'
if (Confirm-Yes '  Build Metasploit image? (~5 min - required for /metasploit skill)') {
    Write-Host '  Building pentest-agent/metasploit...'
    docker build -t pentest-agent/metasploit $MsfCtx
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Metasploit image built: pentest-agent/metasploit'
    } else {
        Write-Warn "Metasploit build failed - run manually: docker build -t pentest-agent/metasploit $MsfCtx"
    }
} else {
    Write-Warn "Metasploit build skipped - run later: docker build -t pentest-agent/metasploit $MsfCtx"
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  Install complete!'
Write-Host '  Codex will spawn the MCP server over stdio on first /pentester invocation.'
Write-Host '  (No Task Scheduler entry needed - Codex manages the MCP lifecycle itself.)'
Write-Host ''
Write-Host '  To rebuild images after adding new skills:'
Write-Host "    docker build -t pentest-agent/kali-mcp $KaliCtx"
Write-Host "    docker build -t pentest-agent/metasploit $MsfCtx"
Write-Host ''
