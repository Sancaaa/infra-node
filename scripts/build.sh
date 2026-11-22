#!/usr/bin/env bash
# Builds the dashboard for the machines it runs on: a Linux VPS (it needs systemd,
# ansible and terraform, so there is no Windows build). The web files are inside
# the program, so each result is one file to copy to the VPS.
set -e
cd "$(dirname "$0")/.."

mkdir -p bin
rm -f bin/*

build() {
  echo ">>> $1/$2"
  CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -ldflags="-s -w" -o "bin/infra-manager-$1-$2" ./cmd/infra-manager
}

build linux amd64   # a normal VPS
build linux arm64   # an ARM VPS or a Raspberry Pi

echo
ls -lh bin/
