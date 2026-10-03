"""Package the built extension and standalone UI for the public download links."""
from pathlib import Path
import json
import shutil
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]


def main():
    dist = ROOT / "extension" / "dist"
    version = json.loads((dist / "manifest.json").read_text())["version"]
    for name in ("popup.js", "brain.js", "background.js", "vendor/wasm/alethech_wasm_bg.wasm"):
        if not (dist / name).is_file():
            raise SystemExit(f"Build extension first: missing {name}")
    desktop = ROOT / "standalone" / "dist" / "alethech.html"
    if not desktop.is_file():
        raise SystemExit("Build standalone HTML first.")
    downloads = ROOT / "downloads"
    downloads.mkdir(exist_ok=True)
    with ZipFile(downloads / f"alethech-extension-v{version}.zip", "w", ZIP_DEFLATED) as archive:
        for path in sorted(dist.rglob("*")):
            if path.is_file() and not path.name.endswith("-test.js"):
                archive.write(path, path.relative_to(dist))
    shutil.copyfile(desktop, downloads / "alethech.html")
    with ZipFile(downloads / f"alethech-offline-viewer-v{version}.zip", "w", ZIP_DEFLATED) as archive:
        archive.write(desktop, "alethech.html")
    print(f"Packaged verified-runtime downloads for extension {version}")


if __name__ == "__main__":
    main()
