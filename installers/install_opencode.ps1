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
# Agent-callable skills (opencode 1.16.0+ `skill({name: "..."})` tool).
# Different layout from commands\: folder-per-skill with a SKILL.md inside,
# discoverable by Smith via the native skill tool instead of bash + cat-ing
# the file like older agent-smith versions had to do.
$OpencodeSkillsDir   = Join-Path $OpencodeConfigDir 'skills'

function Write-Ok    { param([string]$m) Write-Host "OK   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "WARN $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "FAIL $m" -ForegroundColor Red; exit 1 }
function Test-Cmd    { param([string]$name) [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# Windows PowerShell 5.1's Out-File/Set-Content -Encoding utf8 writes a BOM,
# which opencode's JSON parser rejects as a leading-BOM. Write UTF-8 without one.
function Write-TextNoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

# Tolerant JSON read: a missing/empty/whitespace config is a fresh object rather
# than a ConvertFrom-Json exception that would abort the install.
function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return [pscustomobject]@{} }
    $raw = Get-Content $Path -Raw -ErrorAction SilentlyContinue
    if (-not $raw -or -not $raw.Trim()) { return [pscustomobject]@{} }
    try { return ($raw | ConvertFrom-Json) }
    catch { Write-Warn "Existing JSON at $Path is invalid — starting fresh"; return [pscustomobject]@{} }
}

Write-Host ''
Write-Host '  pentest-agent installer (opencode / Windows)'
Write-Host '  ============================================'
Write-Host ''

# Detect-and-offer-to-install instead of hard-failing (shared helper).
. (Join-Path $RepoDir 'installers\_prereqs.ps1')
Invoke-PrereqBootstrap -Need @('docker', 'poetry', 'opencode')

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
$cfg = Read-JsonFile $OpencodeConfig
if (-not $cfg.mcp)         { $cfg | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{}) -Force }
if (-not $cfg.permission)  { $cfg | Add-Member -NotePropertyName permission -NotePropertyValue ([pscustomobject]@{}) -Force }
if (-not $cfg.instructions){ $cfg | Add-Member -NotePropertyName instructions -NotePropertyValue @() -Force }

$entry = [pscustomobject]@{ type = 'remote'; url = 'http://127.0.0.1:7778/sse'; enabled = $true; timeout = 9000000 }
$cfg.mcp | Add-Member -NotePropertyName 'pentest-agent' -NotePropertyValue $entry -Force
# Permissions — broaden auto-approval so both interactive and dashboard-spawned
# opencode keep working without prompts the operator can't answer (the dashboard-
# spawned background opencode is detached from any TTY). The dashboard's
# _spawn_smith() also passes --dangerously-skip-permissions which auto-approves
# "ask" rules but RESPECTS "deny" — see core/api_server.py.
$cfg.permission | Add-Member -NotePropertyName 'doom_loop' -NotePropertyValue 'allow' -Force
foreach ($tool in @('bash', 'edit', 'webfetch')) {
    if (-not $cfg.permission.PSObject.Properties[$tool]) {
        $cfg.permission | Add-Member -NotePropertyName $tool -NotePropertyValue 'allow' -Force
    }
}

# Bump the per-agent iteration cap for `opencode run`. Default is 500 steps,
# which a "thorough" pentest blows past around the 60-70% coverage mark —
# 135 cells x multiple injection tests per cell + finding-filing + qa_replies
# easily totals 1000-1500 turns. 10000 leaves 5x headroom while still
# guaranteeing the run terminates if it ever loops forever.
if (-not $cfg.agent) {
    $cfg | Add-Member -NotePropertyName agent -NotePropertyValue ([pscustomobject]@{}) -Force
}
if (-not $cfg.agent.build) {
    $cfg.agent | Add-Member -NotePropertyName build -NotePropertyValue ([pscustomobject]@{}) -Force
}
if (-not $cfg.agent.build.PSObject.Properties['steps']) {
    $cfg.agent.build | Add-Member -NotePropertyName steps -NotePropertyValue 10000 -Force
}

$claudeMd = Join-Path $RepoDir 'CLAUDE.md'
if ($cfg.instructions -notcontains $claudeMd) { $cfg.instructions += $claudeMd }

Write-TextNoBom -Path $OpencodeConfig -Content ($cfg | ConvertTo-Json -Depth 100)
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
# Recurse so domain-nested skills (skills\<domain>\<name>\SKILL.md) also install.
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Recurse -File -Filter 'SKILL.md' | ForEach-Object {
    $name = $_.Directory.Name
    if ($name -eq 'pentester-opencode') { return }
    Copy-Item -Path $_.FullName -Destination (Join-Path $OpencodeCommandsDir "$name.md") -Force
    $installed++
}
Write-Ok "$installed slash commands installed"

# ── Install agent-callable skills (opencode 1.16.0+ skill() tool) ────────────
# The slash commands above are for HUMAN-typed `/web-exploit` input. Smith
# (the AI agent) needs the same skill content discoverable via opencode's
# native `skill({name: "..."})` tool, which only finds folder-shaped skills
# under one of these documented paths:
#   $env:USERPROFILE\.config\opencode\skills\<name>\SKILL.md   <- canonical
#   $env:USERPROFILE\.claude\skills\<name>\SKILL.md             <- Claude fallback
#   $env:USERPROFILE\.agents\skills\<name>\SKILL.md             <- agent fallback
# Populate the canonical opencode location so Smith can call
# `skill({name: "web-exploit"})` directly instead of round-tripping through
# bash + cat (the workaround pattern in older agent-smith versions).
Write-Host ''
Write-Host 'Installing skills for opencode''s agent-side skill() tool...'
New-Item -ItemType Directory -Path $OpencodeSkillsDir -Force | Out-Null
$agentSkillCount = 0

function Install-AgentSkill {
    param([string]$Name, [string]$Src)
    if (-not (Test-Path $Src)) { return }
    $dstDir = Join-Path $script:OpencodeSkillsDir $Name
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    Copy-Item -Path $Src -Destination (Join-Path $dstDir 'SKILL.md') -Force
    # Carry the refs/ directory alongside so the agent doesn't have to
    # chase relative paths back into the agent-smith repo.
    $refsSrc = Join-Path (Split-Path -Parent $Src) 'refs'
    if (Test-Path $refsSrc) {
        $refsDst = Join-Path $dstDir 'refs'
        if (Test-Path $refsDst) { Remove-Item $refsDst -Recurse -Force }
        Copy-Item -Path $refsSrc -Destination $refsDst -Recurse -Force
    }
    $script:agentSkillCount++
}

# /pentester gets the opencode variant when available
$pentesterSrc = Join-Path $RepoDir 'skills\pentester-opencode\SKILL.md'
if (-not (Test-Path $pentesterSrc)) {
    $pentesterSrc = Join-Path $RepoDir 'skills\pentester.md'
}
Install-AgentSkill -Name 'pentester' -Src $pentesterSrc

# Recurse so domain-nested skills (skills\<domain>\<name>\SKILL.md) also install.
Get-ChildItem -Path (Join-Path $RepoDir 'skills') -Recurse -File -Filter 'SKILL.md' | ForEach-Object {
    $name = $_.Directory.Name
    if ($name -eq 'pentester-opencode') { return }
    Install-AgentSkill -Name $name -Src $_.FullName
}
Write-Ok "$agentSkillCount agent-callable skills installed in $OpencodeSkillsDir"

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
Write-Warn 'Tool approvals: opencode has no auto-approve mechanism. Each MCP tool will prompt'
Write-Warn 'for confirmation on first use in a session — this is expected behaviour.'
Write-Host '  Edit API keys in .env when ready; the bridge is opt-in.'
Write-Host ''
Write-Host '  To rebuild images after adding new skills:'
Write-Host "    docker build -t pentest-agent/kali-mcp $KaliCtx"
Write-Host "    docker build -t pentest-agent/metasploit $MsfCtx"
Write-Host ''
