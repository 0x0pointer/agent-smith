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

Write-Host ''
Write-Host '  pentest-agent installer (Windows)'
Write-Host '  ================================='
Write-Host ''

# ── Prerequisites ────────────────────────────────────────────────────────────
if (-not (Test-Cmd docker))  { Write-Fail 'docker not found — install Docker Desktop with WSL2 backend.' }
if (-not (Test-Cmd poetry))  { Write-Fail 'poetry not found — install via: pipx install poetry' }
if (-not (Test-Cmd claude))  { Write-Fail 'claude not found — install Claude Code: https://docs.anthropic.com/en/docs/claude-code' }
if (-not (Test-Cmd node))    { Write-Warn 'node not found — Mermaid diagrams render client-side only' }
Write-Ok 'Prerequisites satisfied (docker, poetry, claude)'

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
        $cfg = Get-Content $OpencodeConfig -Raw | ConvertFrom-Json
        if (-not $cfg.mcp) { $cfg | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{}) -Force }
        $entry = [pscustomobject]@{
            type    = 'remote'
            url     = 'http://127.0.0.1:7778/sse'
            enabled = $true
            timeout = 9000000
        }
        $cfg.mcp | Add-Member -NotePropertyName 'pentest-agent' -NotePropertyValue $entry -Force
        $cfg | ConvertTo-Json -Depth 100 | Out-File -FilePath $OpencodeConfig -Encoding utf8
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
$missing   = @()
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Directory | ForEach-Object {
    $name = $_.Name
    if ($name -eq 'pentester-opencode') { return }    # client-specific variant
    $src = Join-Path $_.FullName 'SKILL.md'
    if (-not (Test-Path $src)) {
        $missing += $name; return
    }
    $dst = Join-Path $ClaudeSkillsDir $name
    if (Test-Path $dst) { Remove-Item -Path $dst -Recurse -Force }
    Copy-Item -Path $_.FullName -Destination $dst -Recurse -Force
    $installed++
}
Write-Ok "$installed security analysis skills installed"
if ($missing.Count -gt 0) { Write-Warn ("Missing skills: " + ($missing -join ', ')) }

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
        $lines = (Get-Content $EnvFile) | Where-Object { $_ -notmatch "^$Key=" }
        $lines += "$Key=$val"
        $lines | Set-Content -Path $EnvFile -Encoding utf8
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
Set-EnvKey 'OPENAI_API_KEY'        'OpenAI key — FuzzyAI + PyRIT scoring'
Set-EnvKey 'ANTHROPIC_API_KEY'     'Anthropic key — FuzzyAI anthropic provider'
Set-EnvKey 'AZURE_OPENAI_API_KEY'  'Azure OpenAI key — FuzzyAI azure provider'

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

# ── Claude Code permissions (auto-approve pentest-agent tools) ───────────────
Write-Host ''
Write-Host 'Configuring tool permissions (auto-approve pentest-agent tools)...'
$ClaudeSettingsDir = Join-Path $env:USERPROFILE '.claude'
$ClaudeSettings    = Join-Path $ClaudeSettingsDir 'settings.json'
New-Item -ItemType Directory -Path $ClaudeSettingsDir -Force | Out-Null
$settings = if (Test-Path $ClaudeSettings) {
    Get-Content $ClaudeSettings -Raw | ConvertFrom-Json
} else { [pscustomobject]@{} }
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
$settings | ConvertTo-Json -Depth 100 | Out-File -FilePath $ClaudeSettings -Encoding utf8
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
