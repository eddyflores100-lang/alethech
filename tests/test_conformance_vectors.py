"""Conformance test runner.

Loads every JSON vector in conformance/ and runs it through the
appropriate verifier. Asserts the result matches expected_result.

This serves three purposes:
1. Confirms the Python implementation handles every vector correctly.
2. Provides a reference for external implementations (Rust, TypeScript,
   etc.) to test against.
3. Mutation guard: if a check in verify.py is defeated, the
   corresponding invalid_* vectors will start passing when they
   should fail, and the test will catch it.
"""
import json
from pathlib import Path

import pytest

from alethech import crypto
from alethech.canonical import canonical_json, canonical_json_bytes
from alethech.objects import Identity, MemoryCommit


CONF_DIR = Path(__file__).parent.parent / "conformance"


def _load_vectors():
    """Load all .json vectors from conformance/ subdirectories."""
    vectors = []
    if not CONF_DIR.is_dir():
        return vectors
    for path in sorted(CONF_DIR.rglob("*.json")):
        if path.name == "README.md":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            vectors.append((str(path.relative_to(CONF_DIR)), data))
        except Exception as e:
            vectors.append((str(path.relative_to(CONF_DIR)), {"_error": str(e)}))
    return vectors


VECTORS = _load_vectors()


def _verify_commit(identity_dict: dict, commit_dict: dict) -> bool:
    """Reconstruct Identity + MemoryCommit and verify signature."""
    try:
        ident = Identity.from_dict(identity_dict)
        commit = MemoryCommit.from_dict(commit_dict)
        # First check identity self-verifies
        if not ident.verify_self():
            return False
        # Then check commit signature
        return commit.verify(ident.public_key)
    except Exception:
        return False


def _run_vector(vector: dict) -> str:
    """Run a vector and return 'verify_ok', 'verify_fail', or 'verify_error'."""
    if "_error" in vector:
        return "verify_error"

    expected = vector.get("expected_result", "")
    input_data = vector.get("input", {})
    input_type = input_data.get("type", "")

    if input_type == "MemoryCommit":
        ok = _verify_commit(input_data["identity"], input_data["commit"])
        return "verify_ok" if ok else "verify_fail"

    elif input_type == "Identity":
        try:
            ident = Identity.from_dict(input_data["identity"])
            ok = ident.verify_self()
            return "verify_ok" if ok else "verify_fail"
        except Exception:
            return "verify_fail"

    elif input_type == "JCSNumberTest":
        value = input_data["value"]
        expected_canonical = input_data["expected_canonical"]
        actual = canonical_json(value)
        return "verify_ok" if actual == expected_canonical else "verify_fail"

    elif input_type == "UnicodeDistinctness":
        # Just verify the two strings are byte-different (no normalization)
        a = input_data["string_a"]
        b = input_data["string_b"]
        if a.encode("utf-8") != b.encode("utf-8"):
            return "verify_ok"
        return "verify_fail"

    return "verify_error"


@pytest.mark.parametrize(
    "vector_name,vector",
    VECTORS,
    ids=[v[0] for v in VECTORS],
)
def test_conformance_vector(vector_name: str, vector: dict):
    """Run each conformance vector and assert expected result."""
    if "_error" in vector:
        pytest.fail(f"Vector {vector_name} failed to load: {vector['_error']}")

    expected = vector.get("expected_result")
    if expected is None:
        pytest.skip(f"Vector {vector_name} has no expected_result")

    actual = _run_vector(vector)

    assert actual == expected, (
        f"Vector {vector_name} failed:\n"
        f"  description: {vector.get('description', '?')}\n"
        f"  category: {vector.get('category', '?')}\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}\n"
        f"  notes: {vector.get('notes', '')}"
    )


def test_conformance_vectors_exist():
    """Confirm that conformance vectors were generated."""
    assert len(VECTORS) > 0, "No conformance vectors found. Run: python3 conformance/generate_vectors.py"
    # Should have at least one vector per category
    categories = set()
    for _, v in VECTORS:
        cat = v.get("category", "")
        if cat:
            categories.add(cat)
    assert len(categories) >= 5, f"Expected at least 5 categories, got {categories}"
