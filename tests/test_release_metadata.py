"""Release metadata consistency guards.

These tests prevent version/protocol terminology drift across the three
implementations and citation metadata.
"""
from pathlib import Path
import re

import alethech

ROOT = Path(__file__).resolve().parents[1]


def _quoted_version(path: Path, key: str = "version") -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf'^{re.escape(key)}\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, f"{key} not found in {path}"
    return match.group(1)


def test_language_package_versions_match():
    python_version = _quoted_version(ROOT / "pyproject.toml")
    rust_version = _quoted_version(ROOT / "alethech-rs" / "Cargo.toml")

    import json
    ts_version = json.loads(
        (ROOT / "alethech-ts" / "package.json").read_text(encoding="utf-8")
    )["version"]

    assert alethech.__version__ == python_version
    assert rust_version == python_version
    assert ts_version == python_version


def test_citation_uses_current_version_and_protocol_term():
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    python_version = _quoted_version(ROOT / "pyproject.toml")

    assert f'version: "{python_version}"' in citation
    assert "Merkle DAG" not in citation
    assert "hash-linked DAG" in citation
