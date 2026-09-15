[CmdletBinding()]
param(
    [string]$GhidraHome = $env:GHIDRA_INSTALL_DIR,
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$JarPath,
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$ProjectRoot,
    [Parameter(Mandatory)][string[]]$ImportRoot,
    [string]$LogDirectory,
    [ValidateRange(256, 65536)][int]$MemoryMb = 2048
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-GhidraConfiguration $GhidraHome $JavaHome
if (-not $JarPath) {
    $latest = Join-Path (Split-Path -Parent $PSScriptRoot) 'dist/latest-build.json'
    $build = Get-Content -LiteralPath $latest -Raw | ConvertFrom-Json
    if ($build.ghidra_version -ne $config.Version) { throw 'Built extension and installed Ghidra versions differ. Rebuild first.' }
    $JarPath = $build.jar
}
$adapterJar = (Resolve-Path -LiteralPath $JarPath -ErrorAction Stop).Path
if (-not [IO.Path]::IsPathRooted($Mailbox)) { throw 'Mailbox must be an absolute path.' }
$mailboxPath = [IO.Path]::GetFullPath($Mailbox)
New-Item -ItemType Directory -Path $mailboxPath -Force | Out-Null
$allowedProjects = (Resolve-Path -LiteralPath $ProjectRoot -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $allowedProjects -PathType Container)) { throw 'ProjectRoot must be an existing directory.' }
$allowedImports = @($ImportRoot | ForEach-Object {
    $resolved = (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw 'Each ImportRoot must be an existing directory.' }
    $resolved
})
if ($allowedImports.Count -eq 0) { throw 'At least one ImportRoot is required.' }
# Check ownership before removing only the explicit stop sentinel. Never remove a request/response.
$lockPath = Join-Path $mailboxPath 'bridge.lock'
try { $probe = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
catch { throw "Mailbox is owned by another bridge: $mailboxPath" }
try {
    $pending = @(Get-ChildItem -LiteralPath $mailboxPath -File | Where-Object {
        $_.Name -match '^(request|response|processing)([.-]|$)'
    })
    if ($pending.Count) { throw "Pending mailbox files require inspection: $($pending.Name -join ', ')" }
    $stop = Join-Path $mailboxPath 'stop'
    if (Test-Path -LiteralPath $stop) { Remove-Item -LiteralPath $stop -Force }
}
finally { $probe.Dispose() }
if (-not $LogDirectory) { $LogDirectory = Join-Path $mailboxPath 'logs' }
if (-not [IO.Path]::IsPathRooted($LogDirectory)) { throw 'LogDirectory must be absolute.' }
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
$runId = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$argumentFile = Join-Path $LogDirectory ($runId + '.java.args')
$stdout = Join-Path $LogDirectory ($runId + '.stdout.log')
$stderr = Join-Path $LogDirectory ($runId + '.stderr.log')
$arguments = @(
    "-Xmx${MemoryMb}m", '-Xshare:off', '-Djava.awt.headless=true', '-Dfile.encoding=UTF-8',
    '-Duser.language=en', '-Duser.country=US', '-Dlog4j.skipJansi=true',
    '-Djava.system.class.loader=ghidra.GhidraClassLoader', '--enable-native-access=ALL-UNNAMED',
    '-classpath', ((@($adapterJar) + $config.Jars) -join [IO.Path]::PathSeparator),
    'ca.redline.ghidra.HeadlessMain', '--ghidra-home', $config.Root,
    '--mailbox', $mailboxPath, '--project-root', $allowedProjects
)
foreach ($root in $allowedImports) { $arguments += @('--import-root', $root) }
Write-JavaArgumentFile $argumentFile $arguments
$process = Start-Process -FilePath $config.Java -ArgumentList ('"@' + $argumentFile + '"') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$ready = $false
$deadline = [DateTime]::UtcNow.AddSeconds(45)
try {
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) { throw "Bridge exited during startup with code $($process.ExitCode). Inspect $stderr and $stdout" }
        if (Test-Path -LiteralPath $stderr) {
            try {
                $stream = [IO.FileStream]::new($stderr, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                $reader = [IO.StreamReader]::new($stream)
                try { $logText = $reader.ReadToEnd() } finally { $reader.Dispose() }
                if ($logText -match '(?m)^Redline Ghidra bridge ready:') { $ready = $true; break }
            }
            catch [IO.IOException] { if ($process.HasExited) { throw } }
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) { throw 'Bridge did not report ready within 45 seconds.' }
}
catch {
    if (-not $process.HasExited) { Stop-Process -InputObject $process -Force }
    throw "Bridge startup failed; stopped only this startup process. $($_.Exception.Message) Inspect $stderr and $stdout"
}
$record = [ordered]@{ pid = $process.Id; state = 'ready'; ghidra_version = $config.Version;
    mailbox = $mailboxPath; project_root = $allowedProjects; import_roots = $allowedImports;
    stdout = $stdout; stderr = $stderr; arguments = $argumentFile; started_at = [DateTime]::UtcNow.ToString('o') }
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $LogDirectory ($runId + '.launch.json')) -Encoding UTF8
[pscustomobject]$record
