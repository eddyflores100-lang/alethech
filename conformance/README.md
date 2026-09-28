# Conformance Test Vectors

This directory contains adversarial test vectors for the alethech protocol.
Each vector is a JSON file representing an input or scenario that the
verifier MUST handle in a specific way.

The vectors are organized by category, following the structure recommended
by external security audit. They serve three purposes:

1. **Independent verification**: any implementation of the alethech
   protocol (Python, Rust, TypeScript, etc.) can be tested against
   these vectors to confirm conformance.

2. **Adversarial coverage**: each vector tests an edge case that a
   naive implementation might get wrong (signature malleability,
   non-canonical encodings, unicode normalization, etc.).

3. **Mutation guard**: the test suite that consumes these vectors
   fails when the corresponding check in `verify.py` is defeated.

## Vector categories

| Directory | What it tests |
|---|---|
| `valid/` | Correctly signed artifacts that MUST verify |
| `invalid_signature/` | Tampered signatures that MUST be rejected |
| `invalid_key/` | Wrong key types, malformed JWKs, wrong curve |
| `noncanonical/` | Non-canonical Ed25519 signatures, non-canonical JSON |
| `unicode/` | Unicode normalization attacks, visually-equivalent strings |
| `numeric/` | Number serialization edge cases (-0, exponents, precision) |
| `versioning/` | Protocol version mismatches, future/unknown versions |
| `rollback/` | Checkpoint rollback, dark-gap, sequence gaps |
| `revocation/` | Revoked key usage, cutoff_head violations |
| `key_rotation/` | Key rotation chains, post-rotation commits |

## Vector format

Each vector is a JSON file with this schema:

```json
{
  "description": "Human-readable description of what this vector tests",
  "category": "valid|invalid_signature|...",
  "expected_result": "verify_ok|verify_fail|verify_warn",
  "input": {
    "type": "MemoryCommit|EvidenceCommit|Identity|Checkpoint|...",
    "version": 1,
    "...": "artifact fields"
  },
  "notes": "Optional: why this vector exists, what bug it catches"
}
```

## Running conformance tests

```bash
python -m pytest tests/test_conformance_vectors.py -v
```

This loads every vector in this directory, runs it through `verify_store`,
and asserts the result matches `expected_result`.
