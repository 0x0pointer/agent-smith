<#
.SYNOPSIS
    Stable stdio launcher for the pentest-agent MCP server (Windows).

.DESCRIPTION
    PowerShell port of installers/run-mcp-server.sh. stdio MCP clients (Codex)
    spawn this to run the server over stdin/stdout. The project is
    package-mode=false (see pyproject.toml), so mcp_server is NOT installed into
    the Poetry venv and `python -m mcp_server` is only importable with the repo
    on PYTHONPATH — we set it explicitly here instead of relying on the spawn
    cwd. Resolving the venv Python directly (rather than a bare `poetry run`)
    also keeps us working when the client launches us with a minimal PATH.

    Any extra arguments are forwarded to the server (e.g. --transport sse).

.EXAMPLE
    .\run-mcp-server.ps1
    .\run-mcp-server.ps1 --print-python
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'

$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Resolve the venv Python. In PS 5.1 a native command's stderr under
# $ErrorActionPreference='Stop' raises NativeCommandError, so drop EAP locally
# and keep only the stdout string line (the exe path).
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
    Write-Error "Could not determine the pentest-agent virtualenv Python. Run: poetry -C `"$RepoDir`" install --no-interaction (and if 'python' is the Microsoft Store stub, disable that alias so Poetry uses the real interpreter)."
    exit 1
}

if ($ExtraArgs -and ($ExtraArgs -contains '--print-python')) {
    Write-Output $venvPython
    exit 0
}

$env:PYTHONPATH = $RepoDir
# Force UTF-8 mode so the server's non-ASCII startup logging doesn't hit a
# cp1252 UnicodeEncodeError on Windows (see start-mcp-server.ps1).
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $RepoDir
if ($ExtraArgs) {
    & $venvPython -m mcp_server @ExtraArgs
} else {
    & $venvPython -m mcp_server
}
exit $LASTEXITCODE
