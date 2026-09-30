#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/extension/dist"
WASM_OUT="$OUT/vendor/wasm"

command -v wasm-bindgen >/dev/null || {
  echo "wasm-bindgen CLI is required (0.2.129)" >&2
  exit 2
}

rm -rf "$OUT"
mkdir -p "$WASM_OUT"

rustup target add wasm32-unknown-unknown >/dev/null
cargo build --manifest-path "$ROOT/alethech-wasm/Cargo.toml" --target wasm32-unknown-unknown --release

wasm-bindgen \
  "$ROOT/alethech-wasm/target/wasm32-unknown-unknown/release/alethech_wasm.wasm" \
  --target web \
  --out-dir "$WASM_OUT"

# Build popup (ESM, uses WASM)
npx --yes esbuild@0.25.10 "$ROOT/extension/src/popup.ts" \
  --bundle \
  --platform=browser \
  --format=esm \
  --external:./vendor/wasm/alethech_wasm.js \
  --outfile="$OUT/popup.js"

# Build brain content script (IIFE, no WASM, bundles scrypt-js locally)
npx --yes esbuild@0.25.10 "$ROOT/extension/src/brain.ts" \
  --bundle \
  --platform=browser \
  --format=iife \
  --outfile="$OUT/brain.js"

cp "$ROOT/extension/manifest.json" "$OUT/manifest.json"
cp "$ROOT/extension/popup.html" "$OUT/popup.html"
cp "$ROOT/extension/popup.css" "$OUT/popup.css"
cp "$ROOT/extension/PRIVACY.md" "$OUT/PRIVACY.md"
cp "$ROOT/extension/icon.svg" "$OUT/icon.svg" 2>/dev/null || true
cp "$ROOT/extension/icon16.png" "$OUT/icon16.png" 2>/dev/null || true
cp "$ROOT/extension/icon48.png" "$OUT/icon48.png" 2>/dev/null || true
cp "$ROOT/extension/icon128.png" "$OUT/icon128.png" 2>/dev/null || true

echo "Extension built at $OUT"

# Copy scrypt-js for content script (brain.ts loads it via chrome.runtime.getURL)
cp "$ROOT/extension/src/vendor/scrypt-js.min.js" "$OUT/vendor/scrypt-js.min.js"
