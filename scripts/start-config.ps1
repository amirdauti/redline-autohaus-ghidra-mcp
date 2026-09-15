[CmdletBinding()]
param([Parameter(Mandatory)][string]$ConfigPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $keys = @('launcher_script','ghidra_home','java_home','adapter_jar','bridge_dir','project_root','import_roots')
    foreach ($property in $config.PSObject.Properties) {
        if ($keys -notcontains $property.Name) { throw "Unknown launch setting: $($property.Name)" }
    }
    foreach ($key in $keys) { if ($null -eq $config.$key) { throw "Missing launch setting: $key" } }
    $launch = & (Join-Path $PSScriptRoot 'start-bridge.ps1') -GhidraHome $config.ghidra_home `
        -JavaHome $config.java_home -JarPath $config.adapter_jar -Mailbox $config.bridge_dir `
        -ProjectRoot $config.project_root -ImportRoot @($config.import_roots)
    if ($launch.state -ne 'ready') { throw 'The native bridge did not report readiness.' }
    [Console]::Out.WriteLine(($launch | ConvertTo-Json -Compress -Depth 5))
}
catch {
    [Console]::Error.WriteLine('Ghidra startup: ' + $_.Exception.Message)
    exit 1
}
