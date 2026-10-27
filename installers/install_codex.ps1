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

# Windows PowerShell 5.1 writes a BOM with -Encoding utf8; a BOM on the first
# .env line turns the first key into "﻿KEY" (silently ignored). Write
# UTF-8 without a BOM.
function Write-TextNoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

Write-Host ''
Write-Host '  pentest-agent installer (Codex / Windows)'
Write-Host '  ========================================='
Write-Host ''

# Detect-and-offer-to-install instead of hard-failing (shared helper).
. (Join-Path $RepoDir 'installers\_prereqs.ps1')
Invoke-PrereqBootstrap -Need @('docker', 'poetry', 'codex')

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
# Register through run-mcp-server.ps1, NOT a bare `poetry run python -m mcp_server`.
# pyproject has package-mode=false, so mcp_server is not installed into the venv
# and `-m mcp_server` only resolves with the repo on PYTHONPATH — the wrapper sets
# that (and resolves the venv Python) regardless of the cwd/PATH Codex spawns with.
$runScript = Join-Path $RepoDir 'installers\run-mcp-server.ps1'
codex mcp remove pentest-agent 2>$null | Out-Null
codex mcp add pentest-agent -- powershell -NoProfile -ExecutionPolicy Bypass -File $runScript
Write-Ok 'MCP server registered with Codex'

# ── Skills ───────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $CodexSkills -Force | Out-Null
$pentesterDst = Join-Path $CodexSkills 'pentester'
New-Item -ItemType Directory -Path $pentesterDst -Force | Out-Null
Copy-Item -Path (Join-Path $RepoDir 'skills\pentester.md') `
          -Destination (Join-Path $pentesterDst 'SKILL.md') -Force

$installed = 0
# Recurse so domain-nested skills (skills\<domain>\<name>\SKILL.md) also install.
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Recurse -File -Filter 'SKILL.md' | ForEach-Object {
    $skillDir = $_.Directory
    $name = $skillDir.Name
    if ($name -eq 'pentester-opencode') { return }
    $dst = Join-Path $CodexSkills $name
    if (Test-Path $dst) { Remove-Item -Path $dst -Recurse -Force }
    Copy-Item -Path $skillDir.FullName -Destination $dst -Recurse -Force
    $installed++
}
Write-Ok "$installed Codex skills installed"

# ── API keys ─────────────────────────────────────────────────────────────────
# The MCP server loads this checkout's .env (mcp_server/_app.py:_load_dotenv),
# so the keys below power Garak scoring and the optional alert bridges under
# Codex exactly as they do under Claude Code.
$EnvFile = Join-Path $RepoDir '.env'
if (-not (Test-Path $EnvFile) -and (Test-Path (Join-Path $RepoDir '.env.example'))) {
    Copy-Item -Path (Join-Path $RepoDir '.env.example') -Destination $EnvFile
} elseif (-not (Test-Path $EnvFile)) {
    New-Item -Path $EnvFile -ItemType File | Out-Null
}

function Set-EnvKey {
    param([string]$Key, [string]$Description)
    $existing = $null
    Get-Content $EnvFile -ErrorAction SilentlyContinue | Where-Object { $_ -match "^$Key=(.*)$" } | Select-Object -First 1 | ForEach-Object {
        $existing = $Matches[1]
    }
    if ($existing) {
        Write-Host "  $Key already set. New value (Enter to keep):" -NoNewline
    } else {
        Write-Host "  $Key — $Description"
        Write-Host "  Value (Enter to skip):" -NoNewline
    }
    $sec = Read-Host -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    $val  = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null
    if ($val) {
        $lines = @(Get-Content $EnvFile -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch "^$Key=" })
        $lines += "$Key=$val"
        Write-TextNoBom -Path $EnvFile -Content (($lines -join "`r`n") + "`r`n")
        Write-Ok "$Key saved"
    } elseif ($existing) {
        Write-Ok "$Key unchanged"
    } else {
        Write-Warn "$Key skipped"
    }
}

Write-Host ''
Write-Host '  API keys for AI red-teaming tools. Press Enter to skip any.'
Write-Host ''
Set-EnvKey 'OPENAI_API_KEY'            'OpenAI key — Garak scoring'
# Stored as AITEST_ANTHROPIC_API_KEY (not ANTHROPIC_API_KEY) so it never bills
# the Smith agent's own model calls; the server re-exposes it internally.
Set-EnvKey 'AITEST_ANTHROPIC_API_KEY'  'Anthropic API key (sk-ant-...) — Garak anthropic provider'
Set-EnvKey 'AZURE_OPENAI_API_KEY'      'Azure OpenAI key — Garak azure provider'

Write-Host ''
Write-Host '  Telegram bridge (optional) — HIR / status alerts on your phone.'
Set-EnvKey 'TELEGRAM_BOT_TOKEN' 'Bot token from @BotFather (format 123456:ABC-...)'
Set-EnvKey 'TELEGRAM_CHAT_ID'   'Your Telegram chat ID — only this chat is allowlisted'

Write-Host ''
Write-Host '  Slack bridge (optional)'
Set-EnvKey 'SLACK_WEBHOOK_URL' 'Slack incoming webhook URL — https://hooks.slack.com/...'

Write-Host ''
Write-Host '  Discord bridge (optional)'
Set-EnvKey 'DISCORD_WEBHOOK_URL' 'Discord webhook URL — https://discord.com/api/webhooks/...'

Write-Host ''
Set-EnvKey 'STATUS_UPDATE_INTERVAL_MINUTES' 'Status update interval (default 30; 0 disables)'

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

# The Docker daemon must be running to pull/build. Docker Desktop is frequently
# freshly installed (or simply not launched) at this point, so probe the engine
# and, if it is down, offer to start Docker Desktop and wait. If it never comes
# up we SKIP the image steps (everything auto-pulls/builds on first use) rather
# than crashing the installer. `docker info` writes its failure to stderr, which
# under $ErrorActionPreference='Stop' would raise NativeCommandError if merged
# into the pipeline - so drop EAP locally and discard both streams.
function Test-DockerUp {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try   { docker info 2>$null 1>$null; return ($LASTEXITCODE -eq 0) }
    catch { return $false }
    finally { $ErrorActionPreference = $prev }
}

$DockerUp = Test-DockerUp
if (-not $DockerUp) {
    Write-Warn 'Docker daemon is not responding (Docker Desktop may not be running yet).'
    $dockerDesktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path $dockerDesktop) {
        if (Confirm-Yes '  Start Docker Desktop and wait for it now?') {
            Write-Host '  Launching Docker Desktop...'
            Start-Process -FilePath $dockerDesktop | Out-Null
            Write-Host '  Waiting for the Docker engine (up to 180s)...'
            for ($i = 0; $i -lt 60; $i++) {
                Start-Sleep -Seconds 3
                if (Test-DockerUp) { $DockerUp = $true; break }
            }
        }
    } else {
        Write-Warn '  Docker Desktop executable not found at the default path - start it manually.'
    }
    if ($DockerUp) {
        Write-Ok 'Docker engine is up'
    } else {
        Write-Warn 'Docker still not reachable - skipping image pulls/builds.'
        Write-Warn 'They auto-pull/build on first use; or start Docker Desktop and re-run this installer to pre-fetch them.'
    }
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

if ($DockerUp -and (Confirm-Yes '  Pull lightweight scanner images? (~2 min)')) {
    # Discard both streams (2>$null 1>$null) rather than merging stderr with 2>&1:
    # a native command's stderr piped into the success stream raises a terminating
    # NativeCommandError under $ErrorActionPreference='Stop'. Drop EAP too, belt
    # and suspenders, so a single failed pull only warns instead of aborting.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    foreach ($img in $ScannerImages) {
        docker pull $img 2>$null 1>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Pulled $img"
        } else {
            Write-Warn "Failed to pull $img (will auto-pull on first use)"
        }
    }
    $ErrorActionPreference = $prevEAP
} else {
    Write-Warn 'Scanner image pull skipped - images will auto-pull on first use'
}

Write-Host ''
$KaliCtx = Join-Path $RepoDir 'tools\kali\'
if ($DockerUp -and (Confirm-Yes '  Build Kali image? (required for most skills)')) {
    Write-Host ''
    Write-Host '  Choose Kali tool modules (core is always included). Build-time'
    Write-Host '  estimates are approximate and depend on your network speed:'
    Write-Host ''
    Write-Host '    core   (always)  MCP server, recon: nmap/nuclei/httpx/subfinder    ~6 min'
    Write-Host '    web              web/API exploit, fuzzing, injection, JWT, SSL      ~8 min'
    Write-Host '    infra            internal net, AD, credentials, service enum, pivot ~5 min'
    Write-Host '    mobile           Android/iOS reversing + Frida dynamic analysis     ~4 min'
    Write-Host '    cloud            AWS/GCP CLIs, Prowler, ScoutSuite, trivy           ~7 min'
    Write-Host '  (LLM red-team ''ai'' is no longer a Kali module - Garak is its own image, built below.)'
    Write-Host ''
    $kaliArgs = @()
    foreach ($m in @(
        @{ Name = 'web';    Arg = 'INSTALL_WEB';    Def = $true  },
        @{ Name = 'infra';  Arg = 'INSTALL_INFRA';  Def = $true  },
        @{ Name = 'mobile'; Arg = 'INSTALL_MOBILE'; Def = $false },
        @{ Name = 'cloud';  Arg = 'INSTALL_CLOUD';  Def = $false }
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
if ($DockerUp -and (Confirm-Yes '  Build Metasploit image? (~5 min - required for /metasploit skill)')) {
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

Write-Host ''
$GarakCtx = Join-Path $RepoDir 'tools\garak\'
if ($DockerUp -and (Confirm-Default '  Build Garak image now? (~5 min - LLM red-team; else auto-builds on first use)' $false)) {
    Write-Host '  Building pentest-agent/garak...'
    docker build -t pentest-agent/garak $GarakCtx
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Garak image built: pentest-agent/garak'
    } else {
        Write-Warn "Garak build failed - run manually: docker build -t pentest-agent/garak $GarakCtx"
    }
} else {
    Write-Warn "Garak build skipped - auto-builds on first scan(tool='garak'), or run: docker build -t pentest-agent/garak $GarakCtx"
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
