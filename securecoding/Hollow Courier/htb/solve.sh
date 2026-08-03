#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${1:-"$ROOT/src/repository"}

install -m 0644 "$ROOT/htb/app/__init__.py" "$TARGET/checkpoint/app/__init__.py"
install -m 0644 "$ROOT/htb/conf/Caddyfile" "$TARGET/checkpoint/conf/Caddyfile"

printf 'Applied the reference patch to %s\n' "$TARGET"
