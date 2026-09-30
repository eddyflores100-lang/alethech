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

wasm-bindgen   "$ROOT/alethech-wasm/target/wasm32-unknown-unknown/release/alethech_wasm.wasm"   --target web   --out-dir "$WASM_OUT"

npx --yes esbuild "$ROOT/extension/src/popup.ts"   --bundle   --platform=browser   --format=esm   --external:./vendor/wasm/alethech_wasm.js   --outfile="$OUT/popup.js"

cp "$ROOT/extension/manifest.json" "$OUT/manifest.json"
cp "$ROOT/extension/popup.html" "$OUT/popup.html"
cp "$ROOT/extension/popup.css" "$OUT/popup.css"

echo "Extension built at $OUT"
