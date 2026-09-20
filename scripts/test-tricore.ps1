[CmdletBinding()]
param(
    [string]$GhidraHome = $env:GHIDRA_INSTALL_DIR,
    [string]$JavaHome = $env:JAVA_HOME,
    [Parameter(Mandatory)][string]$WorkRoot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-GhidraConfiguration $GhidraHome $JavaHome
$repo = Split-Path -Parent $PSScriptRoot
$build = Get-Content -LiteralPath (Join-Path $repo 'dist/latest-build.json') -Raw | ConvertFrom-Json
if ($build.ghidra_version -ne $config.Version) { throw 'Rebuild the adapter for this installed Ghidra version.' }
if (-not [IO.Path]::IsPathRooted($WorkRoot)) { throw 'WorkRoot must be absolute.' }
$work = Join-Path ([IO.Path]::GetFullPath($WorkRoot)) ('tricore-' + [guid]::NewGuid().ToString('N'))
$classes = Join-Path $work 'classes'
New-Item -ItemType Directory -Path $classes -Force | Out-Null
$classpath = (@($build.jar) + $config.Jars) -join [IO.Path]::PathSeparator
$compileArgs = Join-Path $work 'javac.args'
Write-JavaArgumentFile $compileArgs @('--release', $config.JavaRelease, '-proc:none', '-encoding', 'UTF-8', '-classpath', $classpath, '-d', $classes, (Join-Path $repo 'java/src/test/java/ca/redline/ghidra/FlowTriCoreFixtureMain.java'))
& $config.Javac ('@' + $compileArgs)
if ($LASTEXITCODE -ne 0) { throw 'TriCore fixture compilation failed.' }
$report = Join-Path $work 'report.json'
$arguments = @('-Xmx1024m', '-Xshare:off', '-Djava.awt.headless=true', '-Dfile.encoding=UTF-8',
    '-Djava.system.class.loader=ghidra.GhidraClassLoader', '--enable-native-access=ALL-UNNAMED',
    ('-Dapplication.settingsdir=' + (Join-Path $work 'settings')), ('-Dapplication.cachedir=' + (Join-Path $work 'cache')),
    ('-Dapplication.tempdir=' + (Join-Path $work 'temp')), '-classpath', ($classes + [IO.Path]::PathSeparator + $classpath),
    'ca.redline.ghidra.FlowTriCoreFixtureMain', $config.Root, $report)
$argumentFile = Join-Path $work 'java.args'
Write-JavaArgumentFile $argumentFile $arguments
& $config.Java ('@' + $argumentFile)
if ($LASTEXITCODE -ne 0) { throw 'TriCore fixture execution failed.' }
$result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
if (-not $result.success -or $result.language_id -ne 'tricore:LE:32:tc29x') { throw 'Unexpected TriCore fixture result.' }
[pscustomobject]@{ success = $result.success; language = $result.language_id; report = $report }
