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
# Start-Process cannot point stdout and stderr at the SAME file (unlike the shell
# `>> log 2>&1`), so they are split. stderr -> mcp_sse.log keeps tracebacks and
# the server's logging (which go to stderr) in the file the install/troubleshoot
# messages tell you to check; stdout -> mcp_sse.out.log.
$LogFile = Join-Path $RepoDir 'logs\mcp_sse.log'
$OutFile = Join-Path $RepoDir 'logs\mcp_sse.out.log'
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

    # Resolve the Poetry venv Python. In PS 5.1, a native command writing to
    # stderr while $ErrorActionPreference='Stop' raises NativeCommandError, so
    # drop EAP locally and keep only the stdout string line (the exe path);
    # stderr warnings arrive as ErrorRecord objects and are filtered out.
    $venvPython = $null
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $venvPython = (& poetry -C $RepoDir env info --executable 2>&1 |
                        Where-Object { $_ -is [string] -and $_.Trim() } |
                        Select-Object -First 1)
    } finally { $ErrorActionPreference = $prevEAP }
    if ($venvPython) { $venvPython = $venvPython.Trim() }
    if (-not $venvPython -or -not (Test-Path $venvPython)) {
        Write-Host "FAIL Could not determine the Poetry venv Python (poetry env info --executable returned nothing)."
        Write-Host "     Run:  poetry -C `"$RepoDir`" install --no-interaction"
        Write-Host "     If 'python' on your PATH is the Microsoft Store stub, turn it off under"
        Write-Host "     Settings > Apps > Advanced app settings > App execution aliases so Poetry"
        Write-Host "     builds its venv on the real interpreter, then re-run."
        exit 1
    }

    $env:PYTHONPATH = $RepoDir
    # Force Python into UTF-8 mode. The server prints non-ASCII (e.g. a "→") in
    # its startup logging; Windows defaults stdout/stderr to the ANSI code page
    # (cp1252), which can't encode those and raises UnicodeEncodeError that
    # crashes boot. UTF-8 mode makes stdout/stderr/filesystem UTF-8.
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    # Start-Process with -NoNewWindow + redirected I/O detaches the child so
    # closing this PowerShell session doesn't kill the MCP. The equivalent of
    # nohup on Unix.
    $proc = Start-Process -FilePath $venvPython `
                           -ArgumentList @('-m', 'mcp_server', '--transport', 'sse',
                                            '--host', '127.0.0.1', '--port', "$Port") `
                           -WorkingDirectory $RepoDir `
                           -RedirectStandardOutput $OutFile `
                           -RedirectStandardError $LogFile `
                           -WindowStyle Hidden `
                           -PassThru
    $proc.Id | Out-File -FilePath $PidFile -Encoding ascii -NoNewline

    # Poll until the port accepts a TCP connection (up to 8s). Do NOT probe /sse
    # with Invoke-WebRequest: /sse is an endless Server-Sent-Events stream, and on
    # PS 5.1 Invoke-WebRequest reads the entire response body before returning, so
    # on a never-ending stream it blocks forever (-TimeoutSec caps only the initial
    # response, not the streaming body read — unlike curl's --max-time in the .sh
    # port). A raw TCP connect proves the server is listening without reading it.
    for ($i = 0; $i -lt 16; $i++) {
        $connected = $false
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(1000) -and $client.Connected) {
                $client.EndConnect($async)
                $connected = $true
            }
        } catch { } finally { $client.Close() }
        if ($connected) { break }
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

# Reaching here means no failure path called `exit 1`. Return 0 explicitly so the
# caller's `if ($LASTEXITCODE -ne 0)` check is deterministic — without this, the
# exit code is inherited from the last native command (e.g. the poetry shim),
# which on Windows can be nonzero even on success and spuriously trips the check.
exit 0
