# Rust container CLI verification dependency

`alethech-container-v2` supports `seal`, `recover`, `migrate`, `open-pass`, and
`open-recovery`. Every operation verifies the complete materialized store and
checks that any included portable private signing key belongs to an active identity key
before producing output. The current native Rust verifier implements only part
of protocol verification, so these commands require **Python 3 (`python3` on
PATH) and the matching Alethech Python package**, including its dependencies.
Run from the repository root or install the Python package (`pip install -e .`).

The CLI invokes a fixed Python program directly without a shell. The decrypted
payload travels on stdin; the verifier uses a temporary directory, the Python
`container_v2._materialize_payload` full-history verifier, and
`container._verify_portable_signing_key` when the operational key is present.
Read-only archives may omit that key while retaining full history verification. Missing Python, missing imports, or any
verification failure causes a nonzero exit, no stdout payload, and no output
replacement. This dependency is explicit; native-only full verification is not
claimed.

Container framing and canonical headers, exact schemas, strict unpadded
base64url, allowed payload paths (excluding `authorities/`), and size limits are
validated before verification. Output is written to a fresh file in the target
directory, synchronized, and atomically renamed only after verification and
encryption finish. Unix temporary/output permissions are 0600. A failed write
removes the temporary file. After rename commits the output, directory sync is
best-effort so a post-commit durability error cannot suppress the returned
recovery credentials. Atomic replacement is subject to the platform's
rename semantics (Windows may reject replacement of an existing destination).

The commands preserve the documented single-JSON-response contract. Recovery
retains the container ID and optionally rotates its recovery secret; migration
creates a new container ID without modifying signed protocol history. Recovery
requires exactly one passphrase and one recovery slot; other valid topologies
are rejected to avoid dropping credentials. Migration refuses source path,
symlink, and hard-link aliases unless `--replace-source` is explicitly supplied
(the optional `--no-recovery` flag may be combined in either order).

Validation (Python package must be available):

```sh
cargo test --manifest-path alethech-rs/Cargo.toml
```

The Cargo integration test builds/runs the CLI and delegates its adversarial
fixtures to `tests/test_cli_security.py`. Tests cover authenticated but invalid
histories, malformed recovery framing, invalid schemas/paths/base64url,
private-key mismatch, unavailable verifier, and valid recovery/migration with a
single JSON response. The same script can run directly after `cargo build
--bins --manifest-path alethech-rs/Cargo.toml`.
