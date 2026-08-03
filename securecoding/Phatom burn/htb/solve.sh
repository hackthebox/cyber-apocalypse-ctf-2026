#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${1:-"$ROOT/src/repository"}

install -m 0644 "$ROOT/htb/solution/app/src/routes.ts" "$TARGET/phantom_burn/app/src/routes.ts"
install -m 0644 "$ROOT/htb/solution/app/src/sourceVault.ts" "$TARGET/phantom_burn/app/src/sourceVault.ts"
install -m 0644 "$ROOT/htb/solution/archive-service/src/chainReceipt.ts" "$TARGET/phantom_burn/archive-service/src/chainReceipt.ts"
install -m 0644 "$ROOT/htb/solution/archive-service/src/routes.ts" "$TARGET/phantom_burn/archive-service/src/routes.ts"
install -m 0644 "$ROOT/htb/solution/contracts/src/ReceiptVerifier.sol" "$TARGET/phantom_burn/contracts/src/ReceiptVerifier.sol"
install -m 0644 "$ROOT/htb/solution/contracts/src/ShardRegistry.sol" "$TARGET/phantom_burn/contracts/src/ShardRegistry.sol"

printf 'Applied the reference patch to %s\n' "$TARGET"
