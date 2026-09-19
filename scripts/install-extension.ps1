[CmdletBinding()]
param(
    [string]$GhidraHome = $env:GHIDRA_INSTALL_DIR,
    [string]$JavaHome = $env:JAVA_HOME,
    [Parameter(Mandatory)][string]$Archive,
    [string]$SettingsDirectory,
    [switch]$ReplaceExisting
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-GhidraConfiguration $GhidraHome $JavaHome
if (-not $SettingsDirectory) {
    if (-not $env:APPDATA) { throw 'Specify the Ghidra version-specific -SettingsDirectory.' }
    $SettingsDirectory = Join-Path $env:APPDATA ("ghidra/ghidra_{0}_{1}" -f $config.Version, $config.Release)
}
if (-not [IO.Path]::IsPathRooted($SettingsDirectory)) { throw 'SettingsDirectory must be absolute.' }
$settings = [IO.Path]::GetFullPath($SettingsDirectory)
$extensions = Join-Path $settings 'Extensions'
$destination = Join-Path $extensions 'RedlineGhidraMcp'
$archivePath = (Resolve-Path -LiteralPath $Archive -ErrorAction Stop).Path
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        if (-not $name.StartsWith('RedlineGhidraMcp/', [StringComparison]::Ordinal) -or $name.Split('/') -contains '..' -or $name.Contains(':')) {
            throw "Unexpected or unsafe extension archive entry: $name"
        }
    }
    $entry = $zip.GetEntry('RedlineGhidraMcp/extension.properties')
    if (-not $entry) { throw 'Missing extension.properties.' }
    $reader = [IO.StreamReader]::new($entry.Open())
    try { $properties = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($properties -notmatch '(?m)^name=RedlineGhidraMcp\r?$') { throw 'Unexpected extension name.' }
    $versionLine = '(?m)^version=' + [regex]::Escape($config.Version) + '\r?$'
    if ($properties -notmatch $versionLine) { throw "Extension was not built for Ghidra $($config.Version)." }
    if (-not $zip.GetEntry('RedlineGhidraMcp/lib/RedlineGhidraMcp.jar')) { throw 'Missing discoverable module jar RedlineGhidraMcp.jar. Rebuild the extension with the current build script.' }
}
finally { $zip.Dispose() }
if ((Test-Path -LiteralPath $destination) -and -not $ReplaceExisting) {
    throw "Extension already exists at $destination. Stop its bridge, close Ghidra, then use -ReplaceExisting to preserve it in a backup."
}
New-Item -ItemType Directory -Path $extensions -Force | Out-Null
$stage = Join-Path $settings ('redline-extension-stage-' + [guid]::NewGuid().ToString('N'))
[IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $stage)
$stagedExtension = Join-Path $stage 'RedlineGhidraMcp'
# Every move is between explicit paths under this version's settings directory; no project paths.
$settingsPrefix = $settings.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
foreach ($path in @($destination, $stagedExtension)) {
    if (-not [IO.Path]::GetFullPath($path).StartsWith($settingsPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Extension target escaped settings directory.' }
}
$backup = $null
if (Test-Path -LiteralPath $destination) {
    $existingProperties = Join-Path $destination 'extension.properties'
    if (-not (Test-Path -LiteralPath $existingProperties) -or ([IO.File]::ReadAllText($existingProperties) -notmatch '(?m)^name=RedlineGhidraMcp\r?$')) {
        throw 'Existing directory is not a recognized RedlineGhidraMcp extension.'
    }
    $backup = Join-Path $settings ('redline-extension-backups/RedlineGhidraMcp-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    if (-not [IO.Path]::GetFullPath($backup).StartsWith($settingsPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Backup escaped settings directory.' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $backup) -Force | Out-Null
    Move-Item -LiteralPath $destination -Destination $backup
}
try { Move-Item -LiteralPath $stagedExtension -Destination $destination }
catch {
    if ($backup -and -not (Test-Path -LiteralPath $destination)) { Move-Item -LiteralPath $backup -Destination $destination }
    throw
}
[pscustomobject]@{ installed = $destination; ghidra_version = $config.Version; backup = $backup;
    next_step = 'Restart Ghidra, enable RedlineMcpPlugin in File > Configure > Configure All Plugins, then use Tools > Redline MCP > Start bridge.' }
