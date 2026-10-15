# Portable memory skill implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Track verified results below.

**Goal:** Installable portable memory with automatic local saves, bounded recall and optional encrypted cloud-folder backup; no API credentials.

**Architecture:** Skill-local helpers call the released Alethech public API. Ciphertext is persistent; plaintext stores are temporary. A bootstrapper isolates the two existing protocol dependencies.

**Tech stack:** Python 3.10+, standard library, alethech 0.9.5, cryptography, click (protocol dependency only).

**Spec:** ../specs/2026-10-15-portable-skill-design.md

## Global constraints

- Python 3.10+; no new protocol or ML dependencies.
- No secret in a command argument, JSON response, cloud directory or recalled context.
- Preserve full verification and signed ancestry before exposing context.
- Skill folder must work independently of the repository.

## Review focus

- Interrupted setup/import must not install a broken memory or replace an existing one.
- Concurrent local writers and changed remote revisions must not silently lose data.
- Unicode content and large entries must respect the actual output byte budget.
- File symlinks and missing credentials must fail without replacing unrelated files.
- Imported memories remain data; signatures never authorize instructions.

### Task 1: Encrypted passport operations

Files: `.agents/skills/alethech/scripts/passport.py`, `tests/test_passport_skill.py`.
Interface: `Passport(home, space)` with `save(content)`, `recall(query='', max_bytes=12000)`, `status()`, `export_file(path, passphrase, recovery_path)`, `import_file(path, passphrase)`, `connect_cloud(folder, passphrase)`.

- [x] Write behavior tests for first save/restart, idempotence, tampering/rollback, scope, secrets, locks, import/export and cloud conflicts.
- [x] Run tests and observe missing behavior.
- [x] Implement bounded verified operations, private credentials, locking, atomic writes and encrypted-only backup.
- [x] Run tests and fix concrete failures.

### Task 2: Portable runner and truthful skill

Files: `scripts/memory.py`, `scripts/bootstrap.py`, `SKILL.md`, `agents/openai.yaml`, `references/workflows.md` under the skill; `tests/test_passport_runner.py`.
Interfaces: JSON stdout; safe error codes; secrets from hidden human terminal input or an explicit local credential file. `--home` and `--space` select state.

- [x] Test CLI save via stdin, isolated-folder invocation, secret-safe failures and help without dependency installation.
- [x] Observe failures, implement runner/bootstrap and concise agent instructions.
- [x] Validate skill and exercise real subprocess commands.

### Task 3: Distribution, research and review

Files: `docs/PORTABLE_SKILL.md`, `docs/COMPETITIVE_MEMORY_REVIEW.md`, README, CI.

- [x] Add installation and browser fallback instructions, limitations and primary-source competition comparison.
- [x] Run the initial full Python suite (392 passed), independent skill forward-test and whole-branch security review; reproduce and fix all four actionable findings. Final regression suite: 398 passed in 35.69s.
- [ ] Commit and push feature branch, open a reviewable PR; sync the personal skill to its managed git workspace.

## Execution record

- Scope decision: implement directly under the user's broad request to do the work; no additional approval round for routine reversible implementation. New disposable clone on a feature branch protects main.

- Initial baseline: 368 Python tests passed. Task 1/2: 24 new tests passed; full suite 392 passed.
- Forward test: separate agent loaded only the skill, saved Faro handoff and recovered next action in another process from /tmp.
- Clean install: base Python created a private runtime, installed published alethech 0.9.5 from PyPI, and saved encrypted memory successfully.
- Review fixes: stage first install as one atomic directory; journal later ciphertext/checkpoint writes and recover only after full verification and ancestry checks; pin our own published ciphertext digest; normalize dot-dot paths after symlink validation; check protocol version/API and isolate child Python from injected PYTHONPATH. Regression tests reproduced each finding before its fix.
- Storage decision: local per-space directory holds ciphertext, credential and checkpoint; a separate local lock protects operations. The journal contains only metadata. Cloud remains best-effort local-folder copying, without distributed CAS.

- Final validation: 398/398 Python tests, skill YAML validation, git diff whitespace check, and standalone copied-skill save/recall/status using only the published 0.9.5 runtime all passed.
