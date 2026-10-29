#!/bin/sh
# Build the release binaries into dist/ with their SHA256SUMS and print the
# commit they carry. The same commit always gives the same checksums.
# Usage: scripts/build.sh
set -eu

version=$(git rev-parse --short=7 HEAD)
time=$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd)
rm -rf dist
mkdir dist
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X main.version=$version -X main.buildTime=$time" \
		-o "dist/vinpatel-org-linux-$arch" ./cmd/server
done
(cd dist && sha256sum vinpatel-org-linux-* >SHA256SUMS)
echo "$version"
