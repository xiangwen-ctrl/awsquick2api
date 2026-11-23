#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p dist
export CGO_ENABLED=0
export GOOS=linux

for arch in amd64 arm64; do
  export GOARCH="$arch"
  out="dist/awsquick2api-linux-$arch"
  echo "Building $out ..."
  go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/awsquick2api
done

ls -lh dist/awsquick2api-linux-*
