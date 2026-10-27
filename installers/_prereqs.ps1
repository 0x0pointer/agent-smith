<#
.SYNOPSIS
    Shared prerequisite bootstrap for the Windows installers.

.DESCRIPTION
    Dot-sourced by install.ps1 / install_codex.ps1 / install_opencode.ps1.
    Instead of hard-failing when a prerequisite is missing, this detects what's
    absent (including the Microsoft Store "python" alias stub, which is not a
    real interpreter), offers to install each via winget (prompt-gated, and a
    graceful message if winget is unavailable), refreshes PATH in the current
    session so freshly installed tools are visible, and re-checks.

    Entry point:  Invoke-PrereqBootstrap -Need @('docker','poetry','opencode')
    Recognised need tokens: docker, poetry, claude, opencode, codex.

    Docker Desktop is special: after a fresh install it needs a one-time manual
    setup (license + WSL2 backend, often a reboot) before the daemon works, so
    the bootstrap installs it, explains the steps, and exits so you re-run once
    Docker is up. ASCII-only on purpose so the file is robust regardless of how
    it's saved.
#>

# winget package ids for the CLI clients (verified against the winget source).
$script:ClientWinget = @{
    claude   = 'Anthropic.ClaudeCode'
    opencode = 'SST.opencode'
    codex    = 'OpenAI.Codex'
}

function _POk   { param([string]$m) Write-Host "OK   $m" -ForegroundColor Green }
function _PWarn { param([string]$m) Write-Host "WARN $m" -ForegroundColor Yellow }
function _PErr  { param([string]$m) Write-Host "FAIL $m" -ForegroundColor Red }
function _PInfo { param([string]$m) Write-Host $m }

function _Confirm {
    param([string]$Prompt)
    $ans = Read-Host "$Prompt [Y/n]"
    return ($ans -eq '' -or $ans -match '^[Yy]')
}

# Reload PATH from the registry (Machine + User) so tools winget just added to
# the persistent PATH become callable without opening a new shell.
function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user    = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
}

# Append a directory to the persistent User PATH (and this session) if missing.
function Add-UserPath {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path $Dir)) { return }
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = if ($user) { $user -split ';' } else { @() }
    if ($parts -notcontains $Dir) {
        $newUser = (@($user, $Dir) | Where-Object { $_ }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newUser, 'User')
    }
    if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }
}

function Test-StoreStub {
    param([string]$CmdPath)
    return ($CmdPath -like '*\WindowsApps\*')
}

# A usable Python invocation, preferring the `py` launcher (which the Store stub
# never shadows). Returns 'py', a real python.exe path, or $null.
function Get-PythonLauncher {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return 'py' }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python -and -not (Test-StoreStub $python.Source)) { return $python.Source }
    return $null
}

function Install-Winget {
    param([string]$Id, [string]$Label)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        _PWarn "winget is not available - cannot auto-install $Label. Install it from the Microsoft Store (App Installer), or install $Label manually."
        return $false
    }
    _PInfo "  Installing $Label via winget ($Id) - this may show a UAC prompt..."
    winget install --exact --id $Id --accept-package-agreements --accept-source-agreements
    $ok = ($LASTEXITCODE -eq 0)
    Update-SessionPath
    return $ok
}

function Ensure-Python {
    $launcher = Get-PythonLauncher
    if ($launcher) { _POk "Python present ($launcher)"; return $true }

    $stub = Get-Command python -ErrorAction SilentlyContinue
    if ($stub -and (Test-StoreStub $stub.Source)) {
        _PWarn "The 'python' on PATH is the Microsoft Store alias stub, not a real interpreter."
    } else {
        _PWarn 'Python not found.'
    }
    if (-not (_Confirm '  Install Python 3.12 now?')) { return $false }
    if (-not (Install-Winget 'Python.Python.3.12' 'Python 3.12')) { return $false }

    $launcher = Get-PythonLauncher
    if ($launcher) { _POk "Python installed ($launcher)"; return $true }
    _PWarn "Python installed but not visible yet in this session. If 'python' still resolves to the Store stub, turn it off under Settings > Apps > Advanced app settings > App execution aliases, then open a NEW PowerShell and re-run."
    return $false
}

function Ensure-Poetry {
    if (Get-Command poetry -ErrorAction SilentlyContinue) { _POk 'Poetry present'; return $true }
    if (-not (Ensure-Python)) { _PErr 'Poetry needs a working Python first.'; return $false }
    if (-not (_Confirm '  Install Poetry now (official installer)?')) { return $false }

    $launcher = Get-PythonLauncher
    _PInfo '  Installing Poetry via https://install.python-poetry.org ...'
    try {
        $body = (Invoke-WebRequest -Uri 'https://install.python-poetry.org' -UseBasicParsing).Content
        $tmp = Join-Path $env:TEMP 'install-poetry.py'
        [System.IO.File]::WriteAllText($tmp, $body, (New-Object System.Text.UTF8Encoding($false)))
        if ($launcher -eq 'py') { & py $tmp } else { & $launcher $tmp }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch {
        _PErr "Poetry install failed: $($_.Exception.Message)"
        return $false
    }

    # The official installer prints its bin dir but does not touch PATH on
    # Windows; probe the known locations and wire whichever holds poetry.exe.
    foreach ($d in @("$env:APPDATA\Python\Scripts", "$env:APPDATA\pypoetry\venv\Scripts", "$env:USERPROFILE\.local\bin")) {
        if (Test-Path (Join-Path $d 'poetry.exe')) { Add-UserPath $d }
    }
    Update-SessionPath
    if (Get-Command poetry -ErrorAction SilentlyContinue) { _POk 'Poetry installed'; return $true }
    _PWarn 'Poetry installed but not on PATH in this session. Open a NEW PowerShell and re-run the installer.'
    return $false
}

function Ensure-Docker {
    if (Get-Command docker -ErrorAction SilentlyContinue) { _POk 'Docker present'; return $true }
    _PWarn 'Docker not found.'
    if (-not (_Confirm '  Install Docker Desktop now?')) { return $false }
    if (-not (Install-Winget 'Docker.DockerDesktop' 'Docker Desktop')) { return $false }
    $script:DockerJustInstalled = $true
    return $false   # not usable until first-run setup + (usually) a reboot
}

function Ensure-Client {
    param([string]$Client)
    if (Get-Command $Client -ErrorAction SilentlyContinue) { _POk "$Client present"; return $true }
    _PWarn "$Client not found."
    $id = $script:ClientWinget[$Client]
    if (-not $id) { _PWarn "No known winget package for '$Client' - install it manually."; return $false }
    if (-not (_Confirm "  Install $Client now?")) { return $false }
    if (-not (Install-Winget $id $Client)) { return $false }
    if (Get-Command $Client -ErrorAction SilentlyContinue) { _POk "$Client installed"; return $true }
    _PWarn "$Client installed but not visible yet in this session. Open a NEW PowerShell and re-run."
    return $false
}

function Invoke-PrereqBootstrap {
    param([string[]]$Need)
    $script:DockerJustInstalled = $false

    Write-Host ''
    Write-Host 'Checking prerequisites...'

    $missing = @()
    foreach ($t in $Need) {
        switch ($t) {
            'docker' { if (-not (Ensure-Docker))      { $missing += 'docker' } }
            'poetry' { if (-not (Ensure-Poetry))      { $missing += 'poetry' } }
            default  { if (-not (Ensure-Client $t))   { $missing += $t } }
        }
    }

    if ($script:DockerJustInstalled) {
        Write-Host ''
        _PWarn 'Docker Desktop was just installed and needs a one-time setup:'
        _PWarn '  1. Launch Docker Desktop, accept the license, enable the WSL2 backend.'
        _PWarn '  2. Reboot if prompted, then wait until the tray icon reports "running".'
        _PWarn '  3. Re-run this installer.'
        exit 0
    }

    if ($missing.Count -gt 0) {
        Write-Host ''
        _PErr ('Still missing: ' + ($missing -join ', ') + '. Resolve the above, open a NEW PowerShell, and re-run this installer.')
        exit 1
    }

    _POk ('All prerequisites satisfied (' + ($Need -join ', ') + ')')
}
