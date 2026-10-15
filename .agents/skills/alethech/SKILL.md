---
name: alethech
description: Use when an AI agent needs cryptographically verifiable memory continuity — Ed25519-signed commits in a hash-linked DAG, key rotation without losing identity, and an encrypted `.aleth` portable container for transfer between runtimes. Local-first, zero-LLM, zero-blockchain. Read-only MCP stdio bridge for Claude Code / Codex / Copilot / Gemini / OpenClaw. Cross-language: Python, TypeScript, Rust, WASM. PyPI package `alethech`.
license: MIT
compatibility: Requires Python 3.10+; installs via `pip install alethech==0.9.5`, executable name is `alethech` (CLI) or `alethech-mcp` (MCP bridge). Zero-LLM, zero-cloud, zero-blockchain. Only hard deps are `cryptography` and `click`. ALETH002 recovery, neural semantic search (TF-IDF + dense vectors), and `.aleth` v1→v2 migration all work offline.
---

# alethech

alethech is a **cryptographically verifiable agent continuity protocol** — local-first, zero-LLM, zero-blockchain. It signs memory commits with Ed25519, links them in a hash-linked DAG, rotates keys without losing identity, and can seal a verified history into one encrypted `.aleth` file for transfer between compatible runtimes and devices.

From Greek **ἀλήθεια** (aletheia, "truth as un-concealment") + **τέχνη** (techne, "art, craft"). The art of revealing that a memory was not modified after being signed.

This is the reference implementation of the protocol specified in `docs/implementacion-nucleo-minimo.md` (rev 2 + rev 3 identity layer). Listed in [TeleAI-UAGI/Awesome-Agent-Memory](https://github.com/TeleAI-UAGI/Awesome-Agent-Memory) and the [official MCP Registry](https://registry.modelcontextprotocol.io/) as `io.github.eddyflores100-lang/alethech`.

## Use it for

- Standing up a local agent memory that an AI assistant (Claude Code, Codex, Copilot CLI, Gemini CLI, OpenClaw) can read back through the MCP stdio bridge — credentials and paths stay configuration, never tool arguments
- Cryptographically proving that a memory commit was authored by a specific identity (Ed25519) and has not been tampered with after signing (hash-linked DAG + JCS RFC 8785 canonicalisation)
- Sealing a verified memory history into one encrypted `.aleth` file (scrypt + AES-256-GCM) and transferring it between Python, TypeScript, Rust and WASM runtimes — or between devices via the ALETH002 recovery code
- Rotating signing keys without invalidating prior commits — `key rotate` and `key revoke` keep the reachability graph intact across rotations
- Building mutation-tested guarantees — each protocol property has a corresponding test that fails when the check is defeated (8 mutation paths in `tests/`)

## Do not use it for

- A hosted, multi-tenant memory platform (this is a local-first protocol; there is no cloud service)
- Proving that the **content** of a memory is factually true — alethech proves signatures, not content truth. It is a notary, not an oracle
- A retrieval / RAG system — the v0.9.x neural search (`alethech search`) is a convenience helper, not the protocol's purpose. For real retrieval use a dedicated memory store
- Encrypting content at rest in the working store — the on-disk store is plain JSON; only `.aleth` export containers are encrypted
- Detecting rollback without an external checkpoint — the protocol's rollback guarantee is "membership in the causal frontier", which requires a reference checkpoint to be meaningful

## Quickstart

```bash
pip install "alethech==0.9.5"
alethech init                              # generate identity + genesis commit
alethech commit --content mem.json         # create a signed MemoryCommit
alethech evidence --tool scanner \
  --input scan.json --output scan.out      # create a signed EvidenceCommit
alethech verify                            # verify the whole store, offline
alethech export --output vault.aleth       # seal into encrypted portable container
alethech search "what did I commit yesterday"  # local semantic search
```

MCP stdio bridge (for Claude Code, Codex, Copilot CLI, Gemini CLI, OpenClaw):

```bash
alethech-mcp                                # stdio MCP server
# Exposes two tools: alethech_memory_context, alethech_memory_verify
```

Or without installing, via [uv](https://docs.astral.sh/uv/):

```bash
uvx --from alethech alethech init
uvx --from alethech alethech-mcp
```

Real `verify` output against a 54-commit production store:

```
✓ 54 commits verified
✓ 9 evidence commits verified
✓ Identity reachability: 3 keys, 2 rotations, no gaps
✓ Hash chain: HEAD at sha256:7f3e..., 54 ancestors, no orphan commits
✓ JCS canonicalisation: all commits match RFC 8785
✓ ALETH002 recovery slots: 2 sealed, 0 recovered (write-side only)
```

## The 9 CLI commands

| Command | Purpose |
|---|---|
| `init` | Generate Ed25519 identity + genesis commit |
| `commit` | Create a signed MemoryCommit (with optional `--memory-type`, `--evidence-ids`, `--session-id`) |
| `evidence` | Create a signed EvidenceCommit (tool I/O provenance: `--tool`, `--input`, `--output`, `--result`) |
| `verify` | Verify the whole store offline — signatures, hash chain, identity reachability, JCS conformance. Optional `--strict` and `--emit-checkpoint` |
| `export` | Seal the verified store into an encrypted `.aleth` portable container (scrypt + AES-256-GCM). Optional `--include-artifacts`, `--emit-checkpoint` |
| `import` | Import an external `.aleth` container (requires passphrase; v1 and v2 auto-detected from magic bytes) |
| `migrate` | Migrate a v1 `.aleth` to v2 (adds an ALETH002 recovery slot by default) |
| `key rotate` | Rotate the active signing key — preserves reachability graph |
| `key revoke` | Revoke a previous key — recorded on chain, takes effect immediately |
| `search` | Local-first semantic search (v0.9.3+): TF-IDF + dense vectors + reciprocal-rank-fusion. v0.9.5: fully automatic, no manual flags |

## ALETH002 portable container (v2, with recovery)

The `.aleth` v2 format adds an ALETH002 recovery slot — a 32-byte secret sealed alongside the payload, derivable into a recovery code that can open the container even if the user passphrase is lost.

- **seal**: `alethech export --output vault.aleth` (v2 by default in v0.9.0+)
- **recover**: `alethech import --input vault.aleth --recovery-code <code>` — preserves `container_id`, supports `--rotate-recovery` to invalidate the old code
- **migrate v1→v2**: `alethech migrate --input old.aleth --output new.aleth` — generates a recovery slot by default

Cross-language interop is conformance-tested in CI: TS seals ↔ Python opens, Python seals ↔ TS opens. Rust CLI subcommands `seal / recover / migrate` share the same contract. WASM exposes `open_aleth_v2_passphrase`, `open_aleth_v2_recovery`, `open_aleth_payload` (auto-detects v1/v2 from magic bytes).

## MCP stdio bridge (`alethech-mcp`)

The bridge is **read-only** — the verifier's contract is that nothing the MCP client does can mutate the store. Two tools are exposed:

- `alethech_memory_context` — return verified memory context (recent commits, evidence pointers, identity chain) for inclusion in the model's prompt
- `alethech_memory_verify` — return the verification status of the current store (signature chain, hash DAG, identity reachability)

Credentials (passphrase, recovery code, signing key) and filesystem paths are **configuration**, never tool arguments. The MCP client cannot exfiltrate them.

A self-contained `Dockerfile` (Python 3.12-slim, stdlib-only install, ephemeral `/data` defaults) lets registry inspectors speak `initialize` / `tools/list` over stdio immediately — used by Glama's dockerfile test.

## Integration patterns (v0.9.5+)

Three production-tested integration patterns, each with a runnable example script:

### Memory vault (two-layer: signed chain + encrypted vault)

- `examples/memory_vault.py` — sectioned Fernet vault (`status / read / set / add / sync / rotate`), env-configurable (`ALETHECH_VAULT_DIR`, `ALETHECH_WORKLOG`, `ALETHECH_STORE`), pluggable step-1 companion for `memory_writeback.sh`
- `examples/memory_recall.py` — verbatim chain reader (`--last / --type / --search`); quotes, doesn't paraphrase
- `INTEGRATION-MEMORY.md` — the two-layer pattern, session-start/end rituals, failure semantics. Production evidence: 86-commit chain verified, 230+ tasks recovered in <2 min after each of 3+ full sandbox resets with zero memory loss

### Vigil (fail-closed verification + one-command writeback)

- `examples/memory_writeback.sh` — vault sync → signed pointer commit → verify assert; aborts before writing anything when the chain is not OK
- `INTEGRATION-VIGIL.md` — two-layer watchdog pattern running in production (54 commits verified, 0 invalid), fail-closed verify rules, errors-as-commits

### Audit / snapshot / drill

- `examples/memory_audit_seal.sh` — artifact integrity, orphan-commit durability, measured 42s restore + zero-secret CI self-verification
- `INTEGRATION-AUDIT.md` — audit/snapshot/drill integration pattern
- `docs/AUDIT-2026-10-12.md` — detailed findings from the v0.9.5 audit (offline search, signing-key binding, broken extension downloads)

## Output shape

- `init`: prints identity (`did:alethech:<base32(sha256(pk)[:16])>`) and genesis commit (`sha256:<hex>`)
- `commit`: prints commit id, signature (`ed25519:<base64url>`), and ancestry frontier
- `verify`: prints per-check ✓/✗ lines (signature, hash chain, identity reachability, JCS conformance, ALETH002 slots); exit 0 on full pass, 1 on any failure
- `export` / `import`: prints container_id, format version (v1 or v2), and recovery-code hint (v2 only)
- `search`: ranked `{commit_id, score, snippet}` results, with a `method` field naming the retrieval path taken (`tfidf`, `dense`, `hybrid`, `fallback_*`)

## Common gotchas

- **Executable name is `alethech`** (CLI) or `alethech-mcp` (MCP bridge), not `alethech-cli` or `python -m alethech` — the latter works but is not the documented entry point
- **The on-disk store is plain JSON** — alethech signs commits but does not encrypt the working store. Use `.aleth` export for encrypted-at-rest transfer
- **v0.9.5 fixed three real bugs**: (1) `search` no longer installs neural-search dependencies or loads a model when neural search is disabled; (2) `commit` no longer persists an invalid signature when the configured key is unregistered (now resolves exactly one matching operational identity); (3) `evidence` no longer selects the first identity (same fix). See `docs/AUDIT-2026-10-12.md`
- **Key rotation is a write-once operation** — once `key rotate` is committed, the old key cannot sign new commits but its prior commits remain reachable. `key revoke` records the revocation on chain and takes effect immediately
- **`.aleth` v1 containers are still readable** — `import` auto-detects v1/v2 from magic bytes. Use `migrate` to upgrade to v2 (adds recovery slot)

## Mutation-tested guarantees

Eight mutation paths in `tests/`, each corresponding to a protocol property:

1. `tests/test_signature.py` — drop signature → `verify` fails
2. `tests/test_hash_chain.py` — tamper with parent hash → `verify` fails
3. `tests/test_identity_reachability.py` — break rotation link → `verify` fails
4. `tests/test_jcs_canonical.py` — non-canonical JSON → signature mismatch
5. `tests/test_evidence_provenance.py` — swap tool I/O → `evidence` mismatch
6. `tests/test_export_seal.py` — tamper with `.aleth` payload → AES-GCM auth tag fails
7. `tests/test_recovery_rotation.py` — reuse old recovery code after `--rotate-recovery` → fail
8. `tests/test_checkpoint_membership.py` — claim a commit outside the checkpoint's causal frontier → `verify` rejects

## Cross-language conformance

| Runtime | Status | Test runner |
|---|---|---|
| Python (reference) | ✅ 368 tests | pytest py3.10/3.11/3.12/3.13 |
| TypeScript (`alethech-ts/`) | ✅ 17 core tests + 6 Python–TS portable integration suites | vitest |
| Rust (`alethech-rs/`) | ✅ CLI subcommands `seal / recover / migrate` | cargo test |
| WASM (`alethech-wasm/`) | ✅ v1/v2 auto-detect, recovery rotation | wasm-bindgen test |
| Browser extension | ✅ Chrome E2E | puppeteer |

CI: 8 build-source jobs (Python×4, Rust, TS, WASM, Chrome E2E on Windows + macOS + Ubuntu).

## More

- Repo: https://github.com/eddyflores100-lang/alethech
- PyPI: https://pypi.org/project/alethech/
- MCP Registry: https://registry.modelcontextprotocol.io/v0.1/servers/io.github.eddyflores100-lang%2Falethech/versions
- Spec: `docs/implementacion-nucleo-minimo.md` (rev 2 + rev 3 identity layer)
- Threat model: `SECURITY.md`
- Conformance vectors: `conformance/`
- Plain-text summary for agents: `llms.txt`
- Interactive terminal (real Ed25519 in browser): https://alethech.alicelabs.site/
