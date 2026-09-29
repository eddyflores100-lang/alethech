# Cross-language conformance

This directory holds the **shared test vectors** and the **cross-language
harness** that verify all three alethech implementations (Python, Rust,
TypeScript) agree on the same fixtures.

## What "agreement" means

For each fixture in `valid/`:

1. All three implementations MUST accept it (signature verifies).
2. All three implementations MUST produce **identical canonical bytes**
   for the signed payload. This is the byte-exact contract — same input,
   same hash, same signature, across runtimes.

For each fixture in `invalid_*/`:

1. All three implementations MUST reject it.
2. The rejection reason MAY differ (advisory), but the verdict MUST agree.

## Running the harness

```bash
# All three implementations (requires Python 3.10+, cargo, Node.js 18+):
python conformance/cross_language_check.py

# Only Python (CI without Rust/Node installed):
python conformance/cross_language_check.py --only python

# Skip byte comparison (only check accept/reject agreement):
python conformance/cross_language_check.py --no-byte-compare
```

Exit codes:

- `0`: all three implementations ran and agree on all comparable fixtures.
- `1`: at least one implementation disagrees.
- `2`: a required implementation or runtime is not available in the default three-language run. `--only` is a diagnostic single-runtime mode.

## Fixture format

Each fixture is a JSON file with two sections:

```json
{
  "type": "MemoryCommit",
  "agent_id": "did:alethech:...",
  "key_id": "key-001",
  "commit_id": "sha256:...",
  "signature": "ed25519:...",
  ... (object-specific fields) ...,
  "_test_signer_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "..."
  }
}
```

The `_test_signer_jwk` field is included in test vectors only — it is NOT
part of the protocol. It lets the harness verify the signature without
needing to look up the agent's identity in a store.

## Adding a new implementation

To add a 4th implementation (e.g., Go), create a binary or script that:

1. Takes a fixture path as its single argument.
2. Reads the JSON.
3. Verifies the signature against `_test_signer_jwk`.
4. On success: writes the canonical bytes of the signed payload to
   stdout, exits 0.
5. On failure: writes the error to stderr, exits non-zero.

Then add a `run_go()` function in `cross_language_check.py` mirroring
`run_rust()`.

## Origin

This harness was added in 0.8.2 in response to auditor finding #3:
the README claimed "cross-validation confirms the spec is
language-independent" but no shared harness existed that compared
implementations against the same fixtures. The harness closes that
gap. The claim in the README is now backed by an executable check.
