#!/usr/bin/env bash
# memory_audit_seal.sh — self-contained seal+audit loop for alethech artifact integrity.
# Pattern doc: INTEGRATION-AUDIT.md (this repo). Runs fully offline, 0 AI tokens.
#
#   seal  — hash the ground-truth files and commit the manifest to the chain
#   audit — recompute hashes and compare against the last sealed manifest (exit 0|2)
#
# Adapt ARTIFACTS to your own ground-truth files before first use.
set -euo pipefail
cd "$(dirname "$0")/.."   # run from repo root

STORE=".alethech"
MANIFEST=".agent/artifact_manifest.json"

# ground-truth files your agent's memory depends on (self-excluded: the manifest
# is the carrier — a self-referential hash would DRIFT forever)
ARTIFACTS=(
  ".agent/LESSONS.md"
  ".agent/MEMORY_CARDS.md"
  ".agent/memory_index.json"
  "worklog.md"
)

hashes=$(python3 - "$MANIFEST" "${ARTIFACTS[@]}" << 'PYEOF'
import hashlib, json, os, sys
out = {}
for rel in sys.argv[2:]:
    out[rel] = None
    if os.path.exists(rel):
        h = hashlib.sha256(open(rel, "rb").read()).hexdigest()
        out[rel] = h
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(json.dumps(out))
PYEOF
)
echo "manifest: $MANIFEST"

alethech --store "$STORE" commit --content "$MANIFEST" --type semantic --session "artifact-seal" >/dev/null
echo "sealed into chain: $(alethech --store "$STORE" log 2>/dev/null | tail -1 || echo 'see chain')"

# audit: compare current hashes against the manifest
python3 - "$MANIFEST" "${ARTIFACTS[@]}" << 'PYEOF'
import hashlib, json, sys
m = json.load(open(sys.argv[1]))
bad = 0
for rel in sys.argv[2:]:
    cur = None
    if os.path.exists(rel):
        cur = hashlib.sha256(open(rel, "rb").read()).hexdigest()
    prev = m.get(rel)
    if cur is None:
        print(f"[MISSING] {rel}"); bad += 1
    elif prev and cur != prev:
        print(f"[DRIFT  ] {rel}"); bad += 1
    else:
        print(f"[OK     ] {rel}")
sys.exit(2 if bad else 0)
PYEOF
