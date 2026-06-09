<#
.SYNOPSIS
    pentest-agent installer for opencode (Windows / PowerShell port of install_opencode.sh)

.DESCRIPTION
    Mirrors install_opencode.sh on Windows. Registers the MCP SSE server in
    opencode's config, installs slash commands + the compaction recovery
    plugin, and schedules MCP auto-start via Windows Task Scheduler.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$OpencodeConfigDir   = Join-Path $env:USERPROFILE '.config\opencode'
$OpencodeConfig      = Join-Path $OpencodeConfigDir 'opencode.json'
$OpencodeCommandsDir = Join-Path $OpencodeConfigDir 'commands'
$OpencodePluginsDir  = Join-Path $OpencodeConfigDir 'plugins'

function Write-Ok    { param([string]$m) Write-Host "OK   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "WARN $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "FAIL $m" -ForegroundColor Red; exit 1 }
function Test-Cmd    { param([string]$name) [bool](Get-Command $name -ErrorAction SilentlyContinue) }

Write-Host ''
Write-Host '  pentest-agent installer (opencode / Windows)'
Write-Host '  ============================================'
Write-Host ''

if (-not (Test-Cmd docker))    { Write-Fail 'docker not found — install Docker Desktop with WSL2 backend.' }
if (-not (Test-Cmd poetry))    { Write-Fail 'poetry not found — install via: pipx install poetry' }
if (-not (Test-Cmd opencode))  { Write-Fail 'opencode not found — install from https://opencode.ai' }
Write-Ok 'Prerequisites satisfied (docker, poetry, opencode)'

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

$TaskName = 'agent-smith-mcp-sse'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
}

Write-Host ''
Write-Host 'Starting MCP SSE server...'
& (Join-Path $RepoDir 'installers\start-mcp-server.ps1') restart
if ($LASTEXITCODE -ne 0) { Write-Fail 'MCP SSE server failed to start' }
Write-Ok 'MCP SSE server running on localhost:7778'

# ── Register MCP in opencode.json ────────────────────────────────────────────
New-Item -ItemType Directory -Path $OpencodeConfigDir -Force | Out-Null
$cfg = if (Test-Path $OpencodeConfig) {
    Get-Content $OpencodeConfig -Raw | ConvertFrom-Json
} else { [pscustomobject]@{} }
if (-not $cfg.mcp)         { $cfg | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{}) -Force }
if (-not $cfg.permission)  { $cfg | Add-Member -NotePropertyName permission -NotePropertyValue ([pscustomobject]@{}) -Force }
if (-not $cfg.instructions){ $cfg | Add-Member -NotePropertyName instructions -NotePropertyValue @() -Force }

$entry = [pscustomobject]@{ type = 'remote'; url = 'http://127.0.0.1:7778/sse'; enabled = $true; timeout = 9000000 }
$cfg.mcp | Add-Member -NotePropertyName 'pentest-agent' -NotePropertyValue $entry -Force
$cfg.permission | Add-Member -NotePropertyName 'doom_loop' -NotePropertyValue 'allow' -Force

$claudeMd = Join-Path $RepoDir 'CLAUDE.md'
if ($cfg.instructions -notcontains $claudeMd) { $cfg.instructions += $claudeMd }

$cfg | ConvertTo-Json -Depth 100 | Out-File -FilePath $OpencodeConfig -Encoding utf8
Write-Ok 'opencode config updated (MCP + CLAUDE.md + doom_loop=allow)'

# ── Task Scheduler entry for MCP auto-start ──────────────────────────────────
$startScript = Join-Path $RepoDir 'installers\start-mcp-server.ps1'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$startScript`" start" `
            -WorkingDirectory $RepoDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
              -ExecutionTimeLimit (New-TimeSpan -Days 365)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
                          -Description 'pentest-agent MCP SSE server (auto-start on logon)'
try {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    Write-Ok "Task Scheduler entry '$TaskName' installed"
} catch {
    Write-Warn "Task Scheduler entry skipped (needs elevation): $($_.Exception.Message)"
}

# ── Plugin + slash commands ──────────────────────────────────────────────────
New-Item -ItemType Directory -Path $OpencodeCommandsDir -Force | Out-Null
New-Item -ItemType Directory -Path $OpencodePluginsDir  -Force | Out-Null

Copy-Item -Path (Join-Path $RepoDir 'installers\opencode-pentest-recovery.mjs') `
          -Destination (Join-Path $OpencodePluginsDir 'opencode-pentest-recovery.mjs') -Force
Write-Ok 'Compaction recovery plugin installed'

$pentesterSrc = Join-Path $RepoDir 'skills\pentester-opencode\SKILL.md'
if (-not (Test-Path $pentesterSrc)) { $pentesterSrc = Join-Path $RepoDir 'skills\pentester.md' }
Copy-Item -Path $pentesterSrc -Destination (Join-Path $OpencodeCommandsDir 'pentester.md') -Force
Write-Ok 'pentester command installed'

$installed = 0
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Directory | ForEach-Object {
    $name = $_.Name
    if ($name -eq 'pentester-opencode') { return }
    $src = Join-Path $_.FullName 'SKILL.md'
    if (-not (Test-Path $src)) { return }
    Copy-Item -Path $src -Destination (Join-Path $OpencodeCommandsDir "$name.md") -Force
    $installed++
}
Write-Ok "$installed slash commands installed"

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
    Write-Warn 'Scanner image pull skipped — images will auto-pull on first use'
}

Write-Host ''
$KaliCtx = Join-Path $RepoDir 'tools\kali\'
if (Confirm-Yes '  Build Kali image? (~10 min — required for most skills)') {
    Write-Host '  Building pentest-agent/kali-mcp (this may take a while)...'
    docker build -t pentest-agent/kali-mcp $KaliCtx
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Kali image built: pentest-agent/kali-mcp'
    } else {
        Write-Warn "Kali build failed — run manually: docker build -t pentest-agent/kali-mcp $KaliCtx"
    }
} else {
    Write-Warn "Kali build skipped — run later: docker build -t pentest-agent/kali-mcp $KaliCtx"
}

Write-Host ''
$MsfCtx = Join-Path $RepoDir 'tools\metasploit\'
if (Confirm-Yes '  Build Metasploit image? (~5 min — required for /metasploit skill)') {
    Write-Host '  Building pentest-agent/metasploit...'
    docker build -t pentest-agent/metasploit $MsfCtx
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Metasploit image built: pentest-agent/metasploit'
    } else {
        Write-Warn "Metasploit build failed — run manually: docker build -t pentest-agent/metasploit $MsfCtx"
    }
} else {
    Write-Warn "Metasploit build skipped — run later: docker build -t pentest-agent/metasploit $MsfCtx"
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  Install complete!'
Write-Warn 'Tool approvals: opencode has no auto-approve mechanism. Each MCP tool will prompt'
Write-Warn 'for confirmation on first use in a session — this is expected behaviour.'
Write-Host '  Edit API keys in .env when ready; the bridge is opt-in.'
Write-Host ''
Write-Host '  To rebuild images after adding new skills:'
Write-Host "    docker build -t pentest-agent/kali-mcp $KaliCtx"
Write-Host "    docker build -t pentest-agent/metasploit $MsfCtx"
Write-Host ''
