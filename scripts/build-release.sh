#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="${1:-}"
[[ -n "$VERSION" ]] || {
  printf 'usage: %s VERSION\n' "$0" >&2
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

for arch in amd64 arm64; do
  work="$DIST/web-ssh_${VERSION}_linux_${arch}"
  mkdir -p "$work"
  (
    cd "$ROOT"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w" -o "$work/web-ssh" ./cmd/web-ssh
  )
  tar -C "$work" -czf "$DIST/web-ssh_${VERSION#v}_linux_${arch}.tar.gz" web-ssh
  rm -rf "$work"
done

(
  cd "$DIST"
  sha256sum ./*.tar.gz >checksums.txt
)
