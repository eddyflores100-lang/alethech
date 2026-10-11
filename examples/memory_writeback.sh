#!/usr/bin/env bash
# memory_writeback.sh — close the memory loop in one command.
#
#   1. vault sync        refresh the encrypted .aleth container -> print its new sha256
#   2. pointer commit    sign {"type":"memory-vault","vault_sha256":...} into the chain
#   3. verify            alethech verify — assert "result: OK" or ABORT
#
# The point: the encrypted portable container and the hash-linked chain always
# agree, and NOTHING is written when the chain is not verifiably OK.
#
# Usage:
#   STORE=/path/to/.alethech bash memory_writeback.sh
#
# Step 1 is pluggable. Either pass a sync command that prints (somewhere in its
# output) the new vault sha256:
#   VAULT_SYNC_CMD="python3 my_vault.py sync" STORE=... bash memory_writeback.sh
# or pass the sha directly:
#   VAULT_SHA256=<64 hex chars> STORE=... bash memory_writeback.sh
#
# © 2026 AliceLabs LLC. MIT License.
set -euo pipefail

STORE="${STORE:?set STORE=/path/to/.alethech}"
STORE_ARG="--store ${STORE}"
VAULT_SYNC_CMD="${VAULT_SYNC_CMD:-}"
VAULT_SHA256="${VAULT_SHA256:-}"

command -v alethech >/dev/null 2>&1 || { echo "ABORT: alethech CLI not in PATH (test the exact PATH your agent uses)"; exit 1; }

# [1/3] vault sync -----------------------------------------------------------
echo "[1/3] vault sync…"
if [ -n "$VAULT_SYNC_CMD" ]; then
  OUT=$($VAULT_SYNC_CMD)
  echo "$OUT"
  SHA=$(printf '%s' "$OUT" | grep -oE '[0-9a-f]{64}' | tail -1)
elif [ -n "$VAULT_SHA256" ]; then
  SHA="$VAULT_SHA256"
else
  echo "ABORT: provide VAULT_SYNC_CMD or VAULT_SHA256 (never fabricate the vault sha)"; exit 1
fi
if [ -z "$SHA" ]; then echo "ABORT: could not obtain vault sha256"; exit 1; fi

# [2/3] signed pointer commit ------------------------------------------------
echo "[2/3] pointer commit firmado…"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
printf '{"type":"memory-vault","vault_sha256":"%s"}' "$SHA" > "$TMP"
alethech $STORE_ARG commit --content "$TMP" --type semantic \
  --session "wb-$(date -u +%Y%m%dT%H%M%SZ)"

# [3/3] verify — fail closed --------------------------------------------------
echo "[3/3] verify…"
VERIFY=$(alethech $STORE_ARG verify 2>&1 | tail -1)
echo "$VERIFY"
printf '%s' "$VERIFY" | grep -q "result: OK" || { echo "ABORT: chain NOT verified — nothing else may proceed"; exit 1; }

echo "OK: loop closed — vault -> pointer -> verified chain"
