$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"

    foreach ($arch in @("amd64", "arm64")) {
        $env:GOARCH = $arch
        $out = "dist/awsquick2api-linux-$arch"
        Write-Host "Building $out ..."
        go build -trimpath -ldflags="-s -w" -o $out ./cmd/awsquick2api
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    Write-Host "Done! Artifacts in dist/:"
    Get-ChildItem dist/awsquick2api-linux-* | Select-Object Name, Length
} finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
