#!/bin/bash
#
# solve.sh — The Far Orchard exploit solver
# don't forget to build the binary first, or just use pre build binary that have been provide.
# Usage:
#   1. Fill in values from /launch response (browser or curl)
#   2. Run: ./solve.sh
#
# Or run without .env for local test mode (to test the local Merkle tree):
#   ./solve.sh --local
#

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# change to this dir if you re-build the binary
# SOLVER_BIN="$SCRIPT_DIR/solver/target/release/solver"
SOLVER_BIN="${SOLVER_BIN:-$SCRIPT_DIR/solver/solver}"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $1" >&2; }
ok()    { echo -e "${GREEN}[+]${NC} $1" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" >&2; }
err()   { echo -e "${RED}[-]${NC} $1" >&2; }

# ── Build solver if not present ────────────────────────────────────
if [ ! -f "$SOLVER_BIN" ]; then
    log "Building solver (first run, ~25s)..."
    cd "$SCRIPT_DIR/solver"
    cargo build --release 2>&1 | grep -E "error|Finished"
    cd "$SCRIPT_DIR"
    ok "Solver built."
fi

# ── Local test mode ────────────────────────────────────────────────
if [ "$1" = "--local" ]; then
    log "Local test mode — generating random Merkle tree..."
    echo "" | "$SOLVER_BIN" 2>/dev/null
    PROOF_COUNT=$(echo "" | "$SOLVER_BIN" 2>/dev/null | grep -c "^PROOF=")
    ok "Generated $PROOF_COUNT proofs (local mode)."
    exit 0
fi

# ── Load .env ──────────────────────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
    err ".env file not found!"
    exit 1
fi

set -a
source "$ENV_FILE"
set +a

# Validate required fields
MISSING=""
[ -z "$SERVER_URL" ]      && MISSING="$MISSING SERVER_URL"
[ -z "$INSTANCE_UUID" ]   && MISSING="$MISSING INSTANCE_UUID"
[ -z "$RPC_URL" ]         && MISSING="$MISSING RPC_URL"
[ -z "$SETUP_CONTRACT" ]  && MISSING="$MISSING SETUP_CONTRACT"
[ -z "$PLAYER_WALLET" ]   && MISSING="$MISSING PLAYER_WALLET"
[ -z "$PLAYER_PRIVKEY" ]  && MISSING="$MISSING PLAYER_PRIVKEY"

if [ -n "$MISSING" ]; then
    err "Missing fields in .env:$MISSING"
    exit 1
fi

ok "Config loaded from .env"
log "Server:       $SERVER_URL"
log "Instance UUID: $INSTANCE_UUID"
log "Setup:         $SETUP_CONTRACT"
log "Wallet:        $PLAYER_WALLET"

# ── Fetch Merkle tree ──────────────────────────────────────────────
log "Fetching Merkle tree from server..."
TREE_DATA=$(curl -s "$SERVER_URL/api/info")
if [ -z "$TREE_DATA" ]; then
    err "Cannot reach server at $SERVER_URL/info"
    exit 1
fi

SOLVER_INPUT=$(echo "$TREE_DATA" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"MERKLE_ROOT={d['merkle_root']}\")
for leaf in d['merkle_leaves']:
    print(f\"LEAF={leaf['index']},{leaf['pk_x']},{leaf['seal_id']}\")
" 2>/dev/null)

if [ -z "$SOLVER_INPUT" ]; then
    err "Failed to parse server response."
    exit 1
fi

ok "Got Merkle tree."

# ── Generate exploit proofs ────────────────────────────────────────
log "Generating 8 exploit proofs (this takes several minutes)..."
SOLVER_STDOUT=$(mktemp)
echo "$SOLVER_INPUT" | "$SOLVER_BIN" 2>&1 | tee "$SOLVER_STDOUT" >&2
ALL_PROOFS=$(cat "$SOLVER_STDOUT")
rm -f "$SOLVER_STDOUT"
PROOF_COUNT=$(echo "$ALL_PROOFS" | grep -c "^PROOF=")
ok "Generated $PROOF_COUNT proofs."

# ── Submit each proof to server ────────────────────────────────────
log "Submitting proofs to server for verification..."

# Write proofs to temp file to avoid issues with long lines in while loop
PROOFS_FILE=$(mktemp)
echo "$ALL_PROOFS" > "$PROOFS_FILE"

PROOF_IDX=0
CURRENT_PROOF=""
CURRENT_NULLIFIER=""
CURRENT_SEAL_ID=""

while IFS= read -r line; do
    case "$line" in
        PROOF=*)
            CURRENT_PROOF="${line#PROOF=}"
            ;;
        NULLIFIER=*)
            CURRENT_NULLIFIER="${line#NULLIFIER=}"
            ;;
        SEAL_ID=*)
            CURRENT_SEAL_ID="${line#SEAL_ID=}"
            ;;
        LEAF_INDEX=*)
            CURRENT_LEAF="${line#LEAF_INDEX=}"
            PROOF_IDX=$((PROOF_IDX + 1))

            log "Proof $PROOF_IDX/8 (leaf $CURRENT_LEAF, Far-Seal #$CURRENT_SEAL_ID)..."

            # Write JSON body to temp file (proof hex is too long for -d flag)
            JSON_BODY=$(mktemp)
            python3 -c "
import json
print(json.dumps({
    'proof': '$CURRENT_PROOF',
    'seal_id': int('$CURRENT_SEAL_ID')
}))
" > "$JSON_BODY" 2>/dev/null

            # Submit with UUID as query param
            VERIFY_RESP=$(curl -s -X POST "$SERVER_URL/api/verify?uuid=$INSTANCE_UUID" \
                -H "Content-Type: application/json" \
                -d @"$JSON_BODY" 2>&1)
            rm -f "$JSON_BODY"

            # Parse response
            STATUS=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

            if [ "$STATUS" = "ok" ]; then
                SIG=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signature',''))" 2>/dev/null)
                ORCHARD=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('orchard',''))" 2>/dev/null)
                VERIFIED_NULLIFIER=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('nullifier',''))" 2>/dev/null)

                ok "Proof $PROOF_IDX verified!"

                # Honor on-chain using cast
                log "  Honoring Far-Seal on-chain..."
                CAST_RESULT=$(cast send "$ORCHARD" "honorSeal(uint256,bytes32,bytes)" \
                    "$CURRENT_SEAL_ID" "$VERIFIED_NULLIFIER" "$SIG" \
                    --rpc-url "$RPC_URL" \
                    --private-key "$PLAYER_PRIVKEY" 2>&1)

                if echo "$CAST_RESULT" | grep -q "status               1"; then
                    ok "  Far-Seal #$CURRENT_SEAL_ID honored on-chain!"
                else
                    warn "  Far-Seal #$CURRENT_SEAL_ID may have failed. Check manually."
                fi
            else
                err "Proof $PROOF_IDX failed: $VERIFY_RESP"
            fi
            ;;
    esac
done < "$PROOFS_FILE"

rm -f "$PROOFS_FILE"

# ── Check if solved ────────────────────────────────────────────────
echo ""
log "Checking if challenge is solved..."
SOLVED=$(curl -s "$SERVER_URL/api/flag?uuid=$INSTANCE_UUID" 2>&1)
FLAG=$(echo "$SOLVED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('flag',''))" 2>/dev/null)

if [ -n "$FLAG" ]; then
    ok "CHALLENGE SOLVED!"
    echo ""
    echo "FLAG: $FLAG"
else
    warn "Not solved yet. Check Far-Seal results above."
    echo "Response: $SOLVED"
fi
