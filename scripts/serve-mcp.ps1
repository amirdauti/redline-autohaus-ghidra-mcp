[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerPath,
    [Parameter(Mandatory)][string]$GhidraHome,
    [Parameter(Mandatory)][string]$JavaHome,
    [Parameter(Mandatory)][string]$JarPath,
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$ProjectRoot,
    [Parameter(Mandatory)][string[]]$ImportRoot
)
$ErrorActionPreference = 'Stop'
try {
    if (-not [IO.Path]::IsPathRooted($Mailbox)) { throw 'Mailbox must be absolute.' }
    New-Item -ItemType Directory -Path $Mailbox -Force | Out-Null
    $probe = $null
    $running = $false
    try { $probe = [IO.File]::Open((Join-Path $Mailbox 'bridge.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch [IO.IOException] { $running = $true }
    finally { if ($probe) { $probe.Dispose() } }
    if (-not $running) {
        # Launcher verifies readiness, preserves pending exchanges, and hides the Java process.
        & (Join-Path $PSScriptRoot 'start-bridge.ps1') -GhidraHome $GhidraHome -JavaHome $JavaHome `
            -JarPath $JarPath -Mailbox $Mailbox -ProjectRoot $ProjectRoot -ImportRoot $ImportRoot | Out-Null
    }
    # Keep standard streams inherited. Start-Process or a PowerShell pipeline here would buffer MCP I/O.
    $executable = (Resolve-Path -LiteralPath $ServerPath -ErrorAction Stop).Path
    $processInfo = [Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = $executable
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    # Win32 argv escaping: this argument cannot end in a backslash and contains no embedded quote.
    $mailboxPath = [IO.Path]::GetFullPath($Mailbox).TrimEnd('\')
    if ($mailboxPath.Contains('"')) { throw 'Mailbox contains an invalid quote.' }
    $processInfo.Arguments = '--bridge-dir "' + $mailboxPath + '" --timeout-ms 45000'
    $server = [Diagnostics.Process]::Start($processInfo)
    $server.WaitForExit()
    exit $server.ExitCode
}
catch {
    [Console]::Error.WriteLine('ghidra-mcp launcher: ' + $_.Exception.Message)
    exit 1
}
