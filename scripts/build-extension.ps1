[CmdletBinding()]
param([string]$GhidraHome = $env:GHIDRA_INSTALL_DIR, [string]$JavaHome = $env:JAVA_HOME)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-GhidraConfiguration $GhidraHome $JavaHome
$repo = Split-Path -Parent $PSScriptRoot
$build = Join-Path $repo ('build/extension-' + [guid]::NewGuid().ToString('N'))
$classes = Join-Path $build 'classes'
$stage = Join-Path $build 'stage'
$extension = Join-Path $stage 'RedlineGhidraMcp'
$dist = Join-Path $repo 'dist'
foreach ($directory in @($classes, (Join-Path $extension 'lib'), $dist)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
$sources = @(Get-ChildItem -LiteralPath (Join-Path $repo 'java/src/main/java') -Filter '*.java' -Recurse | Sort-Object FullName | ForEach-Object FullName)
if ($sources.Count -eq 0) { throw 'No Java sources found.' }
$arguments = @('--release', $config.JavaRelease, '-proc:none', '-encoding', 'UTF-8', '-classpath', ($config.Jars -join [IO.Path]::PathSeparator), '-d', $classes) + $sources
$argumentFile = Join-Path $build 'javac.args'
Write-JavaArgumentFile $argumentFile $arguments
& $config.Javac ('@' + $argumentFile)
if ($LASTEXITCODE -ne 0) { throw "javac failed with exit code $LASTEXITCODE" }
# Ghidra's production ClassSearcher only scans module jars whose name starts with
# the enclosing module name. A generic adapter name loads headlessly but hides the GUI plugin.
$jarPath = Join-Path $extension 'lib/RedlineGhidraMcp.jar'
& $config.Jar --create --file $jarPath -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'jar packaging failed.' }
$properties = [IO.File]::ReadAllText((Join-Path $repo 'java/extension.properties')).Replace('@ghidraVersion@', $config.Version).Replace('@date@', (Get-Date -Format 'yyyy-MM-dd'))
[IO.File]::WriteAllText((Join-Path $extension 'extension.properties'), $properties, [Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $repo 'java/Module.manifest') -Destination $extension
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$archive = Join-Path $dist ("ghidra_{0}_{1}_{2}_RedlineGhidraMcp.zip" -f $config.Version, $config.Release, $stamp)
& $config.Jar --create --no-manifest --file $archive -C $stage RedlineGhidraMcp
if ($LASTEXITCODE -ne 0) { throw 'Extension ZIP packaging failed.' }
$result = [ordered]@{ ghidra_version = $config.Version; archive = $archive; jar = $jarPath; classes = $classes; sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() }
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dist 'latest-build.json') -Encoding UTF8
[pscustomobject]$result
