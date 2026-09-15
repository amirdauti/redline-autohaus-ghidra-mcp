[CmdletBinding()]
param(
    [string]$GhidraHome = $env:GHIDRA_INSTALL_DIR,
    [string]$JavaHome = $env:JAVA_HOME,
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$WorkRoot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-GhidraConfiguration $GhidraHome $JavaHome
$serverPath = (Resolve-Path -LiteralPath $Server -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $serverPath -PathType Leaf)) { throw 'Server must be an existing MCP executable.' }
$repo = Split-Path -Parent $PSScriptRoot
$build = Get-Content -LiteralPath (Join-Path $repo 'dist/latest-build.json') -Raw | ConvertFrom-Json
if ($build.ghidra_version -ne $config.Version) { throw 'Rebuild extension for this Ghidra version.' }
if (-not [IO.Path]::IsPathRooted($WorkRoot)) { throw 'WorkRoot must be absolute.' }
$work = Join-Path ([IO.Path]::GetFullPath($WorkRoot)) ('gui-' + [guid]::NewGuid().ToString('N'))
$classes = Join-Path $work 'harness-classes'
New-Item -ItemType Directory -Path $classes -Force | Out-Null
$classpath = (@($build.jar) + $config.Jars) -join [IO.Path]::PathSeparator
$sources = @((Join-Path $repo 'java/src/test/java/ca/redline/ghidra/gui/GuiAcceptanceMain.java'), (Join-Path $repo 'java/src/test/java/ca/redline/ghidra/BridgeGuardsTest.java'))
$compileArgs = Join-Path $work 'javac.args'
Write-JavaArgumentFile $compileArgs (@('--release', $config.JavaRelease, '-proc:none', '-encoding', 'UTF-8', '-classpath', $classpath, '-d', $classes) + $sources)
& $config.Javac ('@' + $compileArgs)
if ($LASTEXITCODE -ne 0) { throw 'GUI harness native compilation failed.' }
$guardArgs = Join-Path $work 'guard-test.args'
Write-JavaArgumentFile $guardArgs @('-classpath', ($classes + [IO.Path]::PathSeparator + $classpath), 'ca.redline.ghidra.BridgeGuardsTest')
& $config.Java ('@' + $guardArgs)
if ($LASTEXITCODE -ne 0) { throw 'Bridge guard checks failed.' }
$mailbox = Join-Path $work 'mailbox'
$arguments = @('-Xmx2048m', '-Xshare:off', '-Djava.awt.headless=false', '-Dfile.encoding=UTF-8', '-Duser.language=en', '-Duser.country=US',
    '-Djava.system.class.loader=ghidra.GhidraClassLoader', '--enable-native-access=ALL-UNNAMED',
    ('-Dapplication.settingsdir=' + (Join-Path $work 'settings')), ('-Dapplication.cachedir=' + (Join-Path $work 'cache')),
    ('-Dapplication.tempdir=' + (Join-Path $work 'temp')), '-classpath', ($classes + [IO.Path]::PathSeparator + $classpath),
    'ca.redline.ghidra.gui.GuiAcceptanceMain', $config.Root, $work, $mailbox)
$argumentFile = Join-Path $work 'java.args'
Write-JavaArgumentFile $argumentFile $arguments
$stdout = Join-Path $work 'gui.stdout.log'
$stderr = Join-Path $work 'gui.stderr.log'
$process = Start-Process -FilePath $config.Java -ArgumentList ('"@' + $argumentFile + '"') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$processHandle = $process.Handle # Retain the native handle so Windows PowerShell 5 can read ExitCode.
try {
    $ready = Join-Path $work 'gui-ready.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    while (-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline -and -not $process.HasExited) { Start-Sleep -Milliseconds 200 }
    if (-not (Test-Path -LiteralPath $ready)) { throw "GUI harness did not become ready. Inspect $stderr and $stdout" }
    & node (Join-Path $repo 'tests/live-gui.mjs') --server $serverPath --bridge-dir $mailbox --work-dir $work
    if ($LASTEXITCODE -ne 0) { throw "GUI MCP acceptance failed. Evidence: $work" }
    if (-not $process.WaitForExit(30000)) { throw 'GUI harness did not finish cleanup within 30 seconds.' }
    $process.Refresh()
    if ($null -eq $process.ExitCode -or $process.ExitCode -ne 0) { throw "Native GUI assertions failed or exit code unavailable. Evidence: $work" }
    $report = Get-Content -LiteralPath (Join-Path $work 'gui-native-report.json') -Raw | ConvertFrom-Json
    if (-not $report.success) { throw "Native GUI report failed. Evidence: $work" }
    $report
}
catch { throw }
finally {
    if (-not $process.HasExited) {
        $done = Join-Path $work 'gui-client-done.json'
        if (-not (Test-Path -LiteralPath $done)) { [IO.File]::WriteAllText($done, '{"success":false,"error":"Harness launcher stopped"}', [Text.UTF8Encoding]::new($false)) }
        if (-not $process.WaitForExit(20000)) { Stop-Process -InputObject $process -Force; Write-Warning 'Terminated only the isolated test JVM after cleanup timed out.' }
    }
    Write-Output ("GUI evidence directory: " + $work)
}
