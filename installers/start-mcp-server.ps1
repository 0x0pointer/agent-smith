<#
.SYNOPSIS
    Start / stop / restart / status of the pentest-agent MCP SSE server (Windows).

.DESCRIPTION
    PowerShell port of installers/start-mcp-server.sh. Behaviour matches the
    Unix script: a single MCP SSE server bound to 127.0.0.1:7778, tracked by
    a PID file under logs/. Uses Poetry's venv Python directly so PYTHONPATH
    isn't polluted by global Python installs.

.PARAMETER Action
    start | stop | restart | status   (default: start)

.EXAMPLE
    .\start-mcp-server.ps1 start
    .\start-mcp-server.ps1 restart
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'stop', 'restart', 'status')]
    [string]$Action = 'start'
)

$ErrorActionPreference = 'Stop'

$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PidFile = Join-Path $RepoDir 'logs\mcp_sse.pid'
$LogFile = Join-Path $RepoDir 'logs\mcp_sse.log'
$Port    = 7778

function Test-PidAlive {
    param([int]$ProcessId)
    try {
        $null = Get-Process -Id $ProcessId -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-TrackedPid {
    if (-not (Test-Path $PidFile)) { return $null }
    try {
        $raw = (Get-Content $PidFile -Raw).Trim()
        if ($raw -match '^\d+$') { return [int]$raw }
    } catch { }
    return $null
}

function Stop-MCP {
    $existing = Get-TrackedPid
    if ($existing -and (Test-PidAlive $existing)) {
        Stop-Process -Id $existing -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $PidFile) { Remove-Item $PidFile -Force -ErrorAction SilentlyContinue }
    Write-Host 'MCP SSE server stopped'
}

function Start-MCP {
    $existing = Get-TrackedPid
    if ($existing -and (Test-PidAlive $existing)) {
        Write-Host "MCP SSE server already running (PID $existing)"
        return
    }

    # Kill any stale listener on the port (Windows equivalent of `lsof -ti | xargs kill`).
    Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path (Join-Path $RepoDir 'logs'))) {
        New-Item -ItemType Directory -Path (Join-Path $RepoDir 'logs') | Out-Null
    }

    $venvPython = & poetry -C $RepoDir env info --executable 2>$null
    if (-not $venvPython) {
        Write-Error 'Could not determine venv Python path — run `poetry install` in the repo first'
        exit 1
    }

    $env:PYTHONPATH = $RepoDir
    # Start-Process with -NoNewWindow + redirected I/O detaches the child so
    # closing this PowerShell session doesn't kill the MCP. The equivalent of
    # nohup on Unix.
    $proc = Start-Process -FilePath $venvPython `
                           -ArgumentList @('-m', 'mcp_server', '--transport', 'sse',
                                            '--host', '127.0.0.1', '--port', "$Port") `
                           -WorkingDirectory $RepoDir `
                           -RedirectStandardOutput $LogFile `
                           -RedirectStandardError $LogFile `
                           -WindowStyle Hidden `
                           -PassThru
    $proc.Id | Out-File -FilePath $PidFile -Encoding ascii -NoNewline

    # Poll /sse for up to 8s to confirm readiness.
    for ($i = 0; $i -lt 16; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/sse" -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
            if ($r.StatusCode -lt 500) { break }
        } catch { }
        Start-Sleep -Milliseconds 500
    }

    if (Test-PidAlive $proc.Id) {
        Write-Host "OK MCP SSE server running (PID $($proc.Id)) on port $Port"
    } else {
        Write-Host "FAIL MCP SSE server failed to start — check $LogFile"
        exit 1
    }
}

switch ($Action) {
    'start'   { Start-MCP }
    'stop'    { Stop-MCP }
    'restart' { Stop-MCP; Start-Sleep -Seconds 1; Start-MCP }
    'status'  {
        $tracked = Get-TrackedPid
        if ($tracked -and (Test-PidAlive $tracked)) {
            Write-Host "running (PID $tracked)"
        } else {
            Write-Host 'not running'
        }
    }
}
