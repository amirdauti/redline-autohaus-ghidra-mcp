Set-StrictMode -Version Latest

function Get-GhidraConfiguration {
    param([string]$GhidraHome, [string]$JavaHome)
    if (-not $GhidraHome) { throw 'Specify -GhidraHome or GHIDRA_INSTALL_DIR.' }
    $ghidraRoot = (Resolve-Path -LiteralPath $GhidraHome -ErrorAction Stop).Path
    $propertiesPath = Join-Path $ghidraRoot 'Ghidra/application.properties'
    $properties = @{}
    foreach ($line in [IO.File]::ReadAllLines($propertiesPath)) {
        if ($line -match '^([^#=]+)=(.*)$') { $properties[$Matches[1]] = $Matches[2] }
    }
    if (-not $JavaHome) {
        $launchProperties = Join-Path $ghidraRoot 'support/launch.properties'
        foreach ($line in [IO.File]::ReadAllLines($launchProperties)) {
            if ($line -match '^JAVA_HOME_OVERRIDE=(.+)$') { $JavaHome = $Matches[1] }
        }
    }
    if (-not $JavaHome) { throw 'Specify -JavaHome, JAVA_HOME, or JAVA_HOME_OVERRIDE in Ghidra launch.properties.' }
    $jdkRoot = (Resolve-Path -LiteralPath $JavaHome -ErrorAction Stop).Path
    $jars = @(Get-ChildItem -LiteralPath (Join-Path $ghidraRoot 'Ghidra') -Filter '*.jar' -Recurse |
        Where-Object { $_.Directory.Name -eq 'lib' -and $_.FullName -notmatch '[/\\]data[/\\]' } |
        Sort-Object FullName | ForEach-Object FullName)
    if ($jars.Count -eq 0) { throw 'No installed Ghidra module jars found.' }
    $java = Join-Path $jdkRoot 'bin/java.exe'
    $javac = Join-Path $jdkRoot 'bin/javac.exe'
    $jar = Join-Path $jdkRoot 'bin/jar.exe'
    foreach ($file in @($java, $javac, $jar)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing JDK executable: $file" }
    }
    [pscustomobject]@{ Root = $ghidraRoot; Jdk = $jdkRoot; Java = $java; Javac = $javac; Jar = $jar;
        Version = $properties['application.version']; Release = $properties['application.release.name'];
        JavaRelease = $properties['application.java.compiler']; Jars = $jars }
}

function Write-JavaArgumentFile {
    param([string]$Path, [string[]]$Arguments)
    $lines = foreach ($argument in $Arguments) {
        if ($argument -match '[\r\n\x00]') { throw 'Java arguments cannot contain newlines or NUL.' }
        '"' + $argument.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    [IO.File]::WriteAllLines($Path, [string[]]$lines, [Text.UTF8Encoding]::new($false))
}
