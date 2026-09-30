"""Build one offline HTML file using the exact extension UI and WASM runtime."""
from pathlib import Path
import base64
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "extension" / "dist"
OUTPUT = ROOT / "standalone" / "dist" / "alethech.html"


def main():
    wasm = DIST / "vendor" / "wasm" / "alethech_wasm_bg.wasm"
    if not wasm.is_file():
        raise SystemExit("Build the extension before building the standalone HTML.")
    source = (ROOT / "extension" / "src" / "popup.ts").read_text()
    source = source.replace(
        'from "./vendor/wasm/alethech_wasm.js"',
        'from "../dist/vendor/wasm/alethech_wasm.js"',
    ).replace("initWasm()", "initWasm({ module_or_path: globalThis.__ALETH_WASM_BYTES__ })")
    # Keep the temporary entry next to popup.ts to preserve its relative imports.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ts", dir=ROOT / "extension" / "src", delete=False) as entry:
        entry.write(source)
        entry_path = Path(entry.name)
    try:
        with tempfile.TemporaryDirectory(prefix="alethech-standalone-build-") as temp:
            bundle = Path(temp) / "app.js"
            subprocess.run([
                "npx", "--yes", "esbuild@0.25.10", str(entry_path), "--bundle",
                "--platform=browser", "--format=iife", f"--outfile={bundle}",
            ], check=True, cwd=ROOT)
            javascript = bundle.read_text().replace("</script", "<\\/script")
    finally:
        entry_path.unlink(missing_ok=True)
    html = (ROOT / "extension" / "popup.html").read_text()
    css = (ROOT / "extension" / "popup.css").read_text()
    html = html.replace('<link rel="stylesheet" href="popup.css">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'script-src \'unsafe-inline\' \'wasm-unsafe-eval\'; style-src \'unsafe-inline\'; '
        'img-src data: blob:; connect-src \'none\'">'
        f"<style>{css}\nbody{{width:auto;max-width:760px;margin:auto}}main{{padding:24px}}</style>")
    encoded = base64.b64encode(wasm.read_bytes()).decode("ascii")
    script = f'globalThis.__ALETH_WASM_BYTES__=Uint8Array.from(atob("{encoded}"),c=>c.charCodeAt(0));\n{javascript}'
    html = html.replace('<script type="module" src="popup.js"></script>', f"<script>{script}</script>")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(html)
    print(f"Offline standalone HTML built at {OUTPUT}")


if __name__ == "__main__":
    main()
