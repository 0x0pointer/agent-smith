<#
.SYNOPSIS
    pentest-agent installer (Windows / PowerShell port of install.sh)

.DESCRIPTION
    Installs and registers the pentest-agent MCP server with Claude Code on
    Windows. Mirrors the behaviour of installers/install.sh but targets the
    Windows-native CLI experience:
        - PowerShell instead of bash
        - shutil.which lookups via where.exe (PATHEXT-aware)
        - Windows Task Scheduler instead of launchd for MCP auto-start
        - Stop-Process / Get-NetTCPConnection instead of lsof + kill -9

    Run from an elevated PowerShell window (Windows Task Scheduler entries
    require administrative privileges to register at logon).

.NOTES
    Prerequisites (all on PATH): docker, poetry, claude. Node.js v18+ optional.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Write-Ok    { param([string]$m) Write-Host "OK   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "WARN $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "FAIL $m" -ForegroundColor Red; exit 1 }

function Test-Cmd { param([string]$name) [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Windows PowerShell 5.1's Out-File/Set-Content -Encoding utf8 writes a BOM,
# which a leading-BOM-intolerant JSON parser (opencode / Claude settings) rejects
# and which turns the first .env key into "﻿KEY" (silently ignored). Write
# UTF-8 without a BOM everywhere we touch a config or .env file.
function Write-TextNoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

# Tolerant JSON read: a missing, empty, or whitespace-only config is a fresh
# object rather than a ConvertFrom-Json exception that would abort the install.
function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return [pscustomobject]@{} }
    $raw = Get-Content $Path -Raw -ErrorAction SilentlyContinue
    if (-not $raw -or -not $raw.Trim()) { return [pscustomobject]@{} }
    try { return ($raw | ConvertFrom-Json) }
    catch { Write-Warn "Existing JSON at $Path is invalid — starting fresh"; return [pscustomobject]@{} }
}

Write-Host ''
Write-Host '  pentest-agent installer (Windows)'
Write-Host '  ================================='
Write-Host ''

# ── Prerequisites ────────────────────────────────────────────────────────────
# Detect-and-offer-to-install instead of hard-failing (shared with the other
# Windows installers). Handles the Microsoft Store "python" stub, Poetry, the
# Claude Code client, and Docker Desktop.
. (Join-Path $RepoDir 'installers\_prereqs.ps1')
Invoke-PrereqBootstrap -Need @('docker', 'poetry', 'claude')
if (-not (Test-Cmd node)) { Write-Warn 'node not found — Mermaid diagrams render client-side only (optional)' }

# ── Skills submodule ─────────────────────────────────────────────────────────
Write-Host ''
Write-Host 'Updating skills submodule from upstream...'
$gitOk = $false
try {
    Push-Location $RepoDir
    git submodule update --init --recursive --remote skills | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $sha = git -C (Join-Path $RepoDir 'skills') rev-parse --short HEAD
        Write-Ok "Skills submodule updated to $sha"
        $gitOk = $true
    }
} catch { }
finally { Pop-Location }
if (-not $gitOk) {
    Write-Warn 'Could not update skills from upstream — falling back to pinned commit'
    git -C $RepoDir submodule update --init --recursive skills | Out-Null
}

# ── Python deps ──────────────────────────────────────────────────────────────
Write-Host ''
Write-Host 'Installing Python dependencies...'
poetry -C $RepoDir install --no-interaction
if ($LASTEXITCODE -ne 0) { Write-Fail 'poetry install failed' }
Write-Ok 'Poetry dependencies installed'

# ── Disarm any stale Task Scheduler entry before restarting MCP ──────────────
$TaskName = 'agent-smith-mcp-sse'
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "Existing Task Scheduler entry '$TaskName' found — disabling so it doesn't race with the restart."
    Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
}

# ── Start MCP SSE daemon ─────────────────────────────────────────────────────
Write-Host ''
Write-Host 'Starting MCP SSE server...'
& (Join-Path $RepoDir 'installers\start-mcp-server.ps1') restart
if ($LASTEXITCODE -ne 0) { Write-Fail 'MCP SSE server failed to start — check logs/mcp_sse.log' }
Write-Ok 'MCP SSE server running on localhost:7778'

# ── Register MCP with Claude Code (SSE) ──────────────────────────────────────
Write-Host ''
Write-Host 'Registering pentest-agent MCP server with Claude Code (SSE)...'
claude mcp remove --scope user pentest-agent 2>$null | Out-Null
claude mcp add --scope user --transport sse pentest-agent http://127.0.0.1:7778/sse
Write-Ok 'MCP server registered with Claude Code'

# ── Register MCP with opencode (if installed) ────────────────────────────────
$OpencodeConfig = Join-Path $env:USERPROFILE '.config\opencode\opencode.json'
if (Test-Path $OpencodeConfig) {
    Write-Host ''
    Write-Host 'Registering pentest-agent MCP server with opencode...'
    try {
        $cfg = Read-JsonFile $OpencodeConfig
        if (-not $cfg.mcp) { $cfg | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{}) -Force }
        $entry = [pscustomobject]@{
            type    = 'remote'
            url     = 'http://127.0.0.1:7778/sse'
            enabled = $true
            timeout = 9000000
        }
        $cfg.mcp | Add-Member -NotePropertyName 'pentest-agent' -NotePropertyValue $entry -Force
        Write-TextNoBom -Path $OpencodeConfig -Content ($cfg | ConvertTo-Json -Depth 100)
        Write-Ok 'MCP server registered with opencode'
    } catch { Write-Warn "opencode registration failed: $($_.Exception.Message)" }
}

# ── Register Task Scheduler entry for MCP auto-start at logon ────────────────
Write-Host ''
Write-Host 'Installing Task Scheduler entry for MCP auto-start...'
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
    Write-Ok "Task Scheduler entry '$TaskName' installed — auto-starts on logon, restarts on failure"
} catch {
    Write-Warn "Could not register Task Scheduler entry (likely needs elevation): $($_.Exception.Message)"
    Write-Warn 'Re-run this script from an elevated PowerShell to enable auto-start.'
}

# ── Skills installation ──────────────────────────────────────────────────────
Write-Host ''
$ClaudeSkillsDir   = Join-Path $env:USERPROFILE '.claude\skills'
$ClaudeCommandsDir = Join-Path $env:USERPROFILE '.claude\commands'
New-Item -ItemType Directory -Path $ClaudeSkillsDir -Force | Out-Null
New-Item -ItemType Directory -Path $ClaudeCommandsDir -Force | Out-Null

Write-Host 'Installing /pentester slash command...'
Copy-Item -Path (Join-Path $RepoDir 'skills\pentester.md') -Destination (Join-Path $ClaudeCommandsDir 'pentester.md') -Force
Write-Ok 'pentester command installed'

Write-Host 'Installing security analysis skills...'
$installed = 0
# Discover skills at BOTH skills\<name>\SKILL.md (flat) and
# skills\<domain>\<name>\SKILL.md (one level of domain nesting, e.g.
# skills\mobile\android-security\). Install target stays flat at the leaf name.
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Recurse -File -Filter 'SKILL.md' | ForEach-Object {
    $skillDir = $_.Directory
    $name = $skillDir.Name
    if ($name -eq 'pentester-opencode') { return }    # client-specific variant
    $dst = Join-Path $ClaudeSkillsDir $name
    if (Test-Path $dst) { Remove-Item -Path $dst -Recurse -Force }
    Copy-Item -Path $skillDir.FullName -Destination $dst -Recurse -Force
    $installed++
}
Write-Ok "$installed security analysis skills installed"

# ── API keys ─────────────────────────────────────────────────────────────────
$EnvFile = Join-Path $RepoDir '.env'
if (-not (Test-Path $EnvFile) -and (Test-Path (Join-Path $RepoDir '.env.example'))) {
    Copy-Item -Path (Join-Path $RepoDir '.env.example') -Destination $EnvFile
} elseif (-not (Test-Path $EnvFile)) {
    New-Item -Path $EnvFile -ItemType File | Out-Null
}

function Set-EnvKey {
    param([string]$Key, [string]$Description)
    $existing = $null
    Get-Content $EnvFile | Where-Object { $_ -match "^$Key=(.*)$" } | Select-Object -First 1 | ForEach-Object {
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
# NOTE: the Garak anthropic key is stored as AITEST_ANTHROPIC_API_KEY (not
# ANTHROPIC_API_KEY) so it never bills the Smith agent's own model calls — the
# server re-exposes it as ANTHROPIC_API_KEY internally (mcp_server/_app.py:_load_dotenv).
Set-EnvKey 'AITEST_ANTHROPIC_API_KEY'  'Anthropic API key (sk-ant-...) — Garak anthropic provider; stored separately from your Smith agent key'
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

Write-Host ''
Write-Host '  Out-of-band (OOB) interaction backend (optional) — blind SSRF/RCE/XXE confirmation.'
Write-Host '    OOB_MODE=interactsh (default, blank) — DNS+HTTP via the bundled interactsh-client.'
Write-Host '    OOB_MODE=http — any HTTP request logger (webhook.site etc.); zero infra.'
Set-EnvKey 'OOB_MODE'         'OOB backend: interactsh (default) or http (blank = interactsh)'
Set-EnvKey 'OOB_SERVER_URL'   'interactsh server URL (blank = public oast.fun) OR your http logger base URL'
Set-EnvKey 'OOB_SERVER_TOKEN' 'Auth token for a self-hosted interactsh server (blank if none)'
Set-EnvKey 'OOB_POLL_URL'     'http mode only: optional poll URL (supports {id}); blank otherwise'

# ── Claude Code permissions (auto-approve pentest-agent tools) ───────────────
Write-Host ''
Write-Host 'Configuring tool permissions (auto-approve pentest-agent tools)...'
$ClaudeSettingsDir = Join-Path $env:USERPROFILE '.claude'
$ClaudeSettings    = Join-Path $ClaudeSettingsDir 'settings.json'
New-Item -ItemType Directory -Path $ClaudeSettingsDir -Force | Out-Null
$settings = Read-JsonFile $ClaudeSettings
if (-not $settings.permissions) {
    $settings | Add-Member -NotePropertyName permissions -NotePropertyValue ([pscustomobject]@{ allow = @() }) -Force
}
if (-not $settings.permissions.allow) {
    $settings.permissions | Add-Member -NotePropertyName allow -NotePropertyValue @() -Force
}
$entry = 'mcp__pentest-agent__*'
if ($settings.permissions.allow -notcontains $entry) {
    $settings.permissions.allow += $entry
}
Write-TextNoBom -Path $ClaudeSettings -Content ($settings | ConvertTo-Json -Depth 100)
Write-Ok 'pentest-agent tools auto-approved'

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
# into the pipeline — so drop EAP locally and discard both streams.
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
        Write-Warn '  Docker Desktop executable not found at the default path — start it manually.'
    }
    if ($DockerUp) {
        Write-Ok 'Docker engine is up'
    } else {
        Write-Warn 'Docker still not reachable — skipping image pulls/builds.'
        Write-Warn 'They auto-pull/build on first use; or start Docker Desktop and re-run this installer to pre-fetch them.'
    }
}

# Lightweight scanner images — pulled, not built
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
    Write-Warn 'Scanner image pull skipped — images will auto-pull on first use'
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
        Write-Warn "Kali build failed — run manually: docker build -t pentest-agent/kali-mcp $KaliCtx"
    }
} else {
    Write-Warn "Kali build skipped — run later: docker build -t pentest-agent/kali-mcp $KaliCtx"
}

Write-Host ''
$MsfCtx = Join-Path $RepoDir 'tools\metasploit\'
if ($DockerUp -and (Confirm-Yes '  Build Metasploit image? (~5 min — required for /metasploit skill)')) {
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

Write-Host ''
$GarakCtx = Join-Path $RepoDir 'tools\garak\'
if ($DockerUp -and (Confirm-Default '  Build Garak image now? (~5 min - LLM red-team; else auto-builds on first use)' $false)) {
    Write-Host '  Building pentest-agent/garak...'
    docker build -t pentest-agent/garak $GarakCtx
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Garak image built: pentest-agent/garak'
    } else {
        Write-Warn "Garak build failed — run manually: docker build -t pentest-agent/garak $GarakCtx"
    }
} else {
    Write-Warn "Garak build skipped — auto-builds on first scan(tool='garak'), or run: docker build -t pentest-agent/garak $GarakCtx"
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  Install complete!'
Write-Host ''
Write-Host '  Available commands:'
Write-Host '    /pentester scan https://target.com depth=thorough'
Write-Host '    /api-security https://api.example.com'
Write-Host '    /analyze-cve <pkg> <ver> <cve>'
Write-Host '    /threat-model'
Write-Host '    /ai-redteam https://ai-app.com/api/chat'
Write-Host '    /cloud-security my-aws-account provider=aws'
Write-Host '    /metasploit 10.0.0.5 cve=CVE-2017-0144'
Write-Host '    /gh-export'
Write-Host ''
Write-Host '  To rebuild images after adding new skills:'
Write-Host "    docker build -t pentest-agent/kali-mcp $KaliCtx"
Write-Host "    docker build -t pentest-agent/metasploit $MsfCtx"
Write-Host ''
