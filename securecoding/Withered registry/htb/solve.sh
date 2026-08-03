#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${1:-"$ROOT/src/repository"}

install -m 0644 "$ROOT/htb/solution/internal/server/routes.go" "$TARGET/registry-backend/internal/server/routes.go"

printf 'Applied the reference patch to %s\n' "$TARGET"
