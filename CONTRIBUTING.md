# Contributing to alethech

Thank you for your interest in contributing to alethech! This document describes how to contribute.

## Development setup

```bash
git clone https://github.com/eddyflores100-lang/alethech.git
cd alethech
pip install -e ".[dev]"
```

## Running tests

```bash
python -m pytest tests/ -v
```

All 338 tests must pass before any merge.

## Cross-language conformance

The protocol ships three implementations (Python, Rust, TypeScript). They
must agree byte-for-byte on the same fixtures — that contract is enforced
by the cross-language harness, not by any single language's test suite.

```bash
# All three runtimes (requires Python 3.10+, cargo, Node.js 18+):
python conformance/cross_language_check.py

# Python only — the mode to use when cargo/Node are unavailable:
python conformance/cross_language_check.py --only python
```

Exit codes: `0` = all implementations agree on every comparable fixture;
`1` = at least one disagrees; `2` = a required runtime is missing (use
`--only` to diagnose). `--no-byte-compare` checks accept/reject agreement
only, skipping the canonical-bytes comparison.

The full CI job (`.github/workflows/ci.yml`, "cross-language conformance")
goes further than the harness: it seals a container in Python, opens it in
TypeScript and Rust, rejects wrong passphrases, tampered and truncated
containers across all three, rotates passphrases, and round-trips ALETH002
recovery codes between runtimes. If your change touches canonicalization,
crypto, or the container format, that job is the bar your PR has to clear.
Details: [conformance/CROSS_LANGUAGE.md](conformance/CROSS_LANGUAGE.md)
and [conformance/README.md](conformance/README.md).

## Mutation testing

alethech uses mutation-guard paths — tests that are designed to fail when a specific guarantee is defeated. If you change `verify.py` or `cli.py`, verify that:

1. All tests pass
2. The 8 mutation paths still detect their defeats (see `tests/test_revoked_key_reachability.py`)

## Code style

- Python 3.10+ (use type hints where possible)
- No external dependencies beyond `cryptography` and `click`
- No LLM calls, no network calls, no cloud dependencies
- All new features must have adversarial tests

## Pull request process

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Make changes
4. Run tests: `python -m pytest tests/`
5. Run conformance: `python -m pytest tests/test_conformance_vectors.py`
6. Commit with clear message
7. Open a PR

## Adding new test vectors

Conformance vectors live in `conformance/`. Each vector is a JSON file with:

```json
{
  "description": "What this vector tests",
  "category": "valid|invalid_signature|invalid_key|numeric|unicode",
  "expected_result": "verify_ok|verify_fail",
  "input": { ... },
  "notes": "Why this vector exists"
}
```

Run `python3 conformance/generate_vectors.py` to regenerate.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do NOT open public issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
