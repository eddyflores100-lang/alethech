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

All 230 tests must pass before any merge.

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
