#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

# Version injected into main.appVersion (override with VERSION=...).
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"

mkdir -p dist
export CGO_ENABLED=0
export GOOS=linux

for arch in amd64 arm64; do
  export GOARCH="$arch"
  out="dist/awsquick2api-linux-$arch"
  echo "Building $out (version $VERSION) ..."
  go build -trimpath -ldflags="-s -w -X main.appVersion=$VERSION" -o "$out" ./cmd/awsquick2api
done

ls -lh dist/awsquick2api-linux-*
