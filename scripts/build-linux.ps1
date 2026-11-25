$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    # Version injected into main.appVersion (override with $env:VERSION).
    $version = $env:VERSION
    if (-not $version) {
        $version = (git describe --tags --always --dirty 2>$null)
        if ($LASTEXITCODE -ne 0 -or -not $version) { $version = "dev" }
    }
    $version = "$version".Trim().TrimStart("v")

    New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"

    foreach ($arch in @("amd64", "arm64")) {
        $env:GOARCH = $arch
        $out = "dist/awsquick2api-linux-$arch"
        Write-Host "Building $out (version $version) ..."
        go build -trimpath -ldflags="-s -w -X main.appVersion=$version" -o $out ./cmd/awsquick2api
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    Write-Host "Done! Artifacts in dist/:"
    Get-ChildItem dist/awsquick2api-linux-* | Select-Object Name, Length
} finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
