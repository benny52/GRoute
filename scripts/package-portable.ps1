# Builds dist\GRoute-portable-windows-amd64.zip from the current frontend/dist.
# Rebuild the UI first (npm --prefix frontend run build). Supply a directory
# with the pinned client binaries, or prepare bin/ with scripts/fetch-deps.ps1.
# Requires PowerShell on Windows x64 and the Go toolchain specified in go.mod.
#Requires -Version 5.1
param([string]$RuntimeDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin'))

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$runtime = (Resolve-Path -LiteralPath $RuntimeDir).Path
$deps = Get-Content -Raw (Join-Path $root 'build/deps.json') | ConvertFrom-Json
$pins = [ordered]@{}
$pins[$deps.hysteria.dest] = $deps.hysteria.sha256
foreach ($dep in $deps.xray, $deps.windivert) {
    foreach ($file in $dep.files.PSObject.Properties) {
        $pins[[IO.Path]::GetFileName($file.Name)] = $file.Value
    }
}
$files = [ordered]@{}
foreach ($name in $pins.Keys) {
    $path = Join-Path $runtime $name
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $pins[$name]) {
        throw "SHA-256 mismatch: $name (build/deps.json)"
    }
    $files[$name] = $path
}

$work = Join-Path $root '.work'
$stage = Join-Path $work ('package-' + [guid]::NewGuid().ToString('N'))
$exe = Join-Path $stage 'GRoute.exe'
$zipName = 'GRoute-portable-windows-amd64.zip'
$zip = Join-Path $stage $zipName
$dist = Join-Path $root 'dist'
$savedEnvironment = @{}
function Set-BuildEnvironment($name, $value) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, $value)
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Push-Location $root
try {
    $go = 'go'
    if (Test-Path -LiteralPath (Join-Path $work 'go/bin/go.exe')) {
        $go = Join-Path $work 'go/bin/go.exe'
        Set-BuildEnvironment 'GOROOT' (Join-Path $work 'go')
        Set-BuildEnvironment 'GOPATH' (Join-Path $work 'gopath')
        Set-BuildEnvironment 'GOCACHE' (Join-Path $work 'gocache')
    }
    Set-BuildEnvironment 'GOOS' 'windows'
    Set-BuildEnvironment 'GOARCH' 'amd64'
    Set-BuildEnvironment 'CGO_ENABLED' '0'
    $ldflags = '-H windowsgui -X main.portableBuild=true -X main.version=v0.0.0-dev -X main.updateRepo='
    & $go build -trimpath -buildvcs=false -tags desktop,production -ldflags $ldflags -o $exe ./cmd/hyroute
    if ($LASTEXITCODE -ne 0) { throw 'Failed to build GRoute.exe' }
    # Apply resources only to the staged executable. Existing .syso resources
    # used by the upstream builder may request elevation at startup.
    & $go run "github.com/tc-hib/go-winres@$($deps.tools.goWinres)" patch --delete --no-backup --in build/windows/groute-portable.json $exe
    if ($LASTEXITCODE -ne 0) { throw 'Failed to embed GRoute resources' }
    $files['GRoute.exe'] = $exe
    $files['LICENSE.txt'] = Join-Path $root 'LICENSE'
    $files['THIRD-PARTY-NOTICES.txt'] = Join-Path $root 'THIRD-PARTY-NOTICES.txt'

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($zip, 'Create')
    try {
        foreach ($name in $files.Keys) {
            $entry = $archive.CreateEntry($name, 'Optimal')
            $entry.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $stream = $entry.Open()
            try {
                $inputFile = [IO.File]::OpenRead($files[$name])
                try { $inputFile.CopyTo($stream) } finally { $inputFile.Dispose() }
            } finally { $stream.Dispose() }
        }
    } finally { $archive.Dispose() }
    # Check the bytes in the finished archive, including externally sourced
    # files which could have changed between the initial check and compression.
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($name in $files.Keys) {
            $stream = $archive.GetEntry($name).Open()
            try { $hash = (Get-FileHash -Algorithm SHA256 -InputStream $stream).Hash }
            finally { $stream.Dispose() }
            $want = $pins[$name]
            if (!$want) { $want = (Get-FileHash -Algorithm SHA256 -LiteralPath $files[$name]).Hash }
            if ($hash -ne $want) { throw "ZIP verification failed: $name" }
        }
    } finally { $archive.Dispose() }
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    $target = Join-Path $dist $zipName
    if ([IO.File]::Exists($target)) {
        [IO.File]::Replace($zip, $target, [NullString]::Value)
    } else {
        [IO.File]::Move($zip, $target)
    }
    Get-FileHash -Algorithm SHA256 -LiteralPath $target
} finally {
    Pop-Location
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name])
    }
    if ((Split-Path -Parent (Resolve-Path -LiteralPath $stage).Path) -eq $work) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
