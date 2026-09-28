# Integration: alethech + memex

> Make every memex memory cryptographically verifiable — without changing memex.

## STATUS — read this first

**The implementation works. 121 tests passing. 6 bugs found and fixed.**

What is implemented and tested:
- Identity creation (Ed25519, SHA-256, agent_id derivation with JWK validation)
- MemoryCommit signing and verification
- Key rotation (atomic, with cutoff_head existence check)
- Migration from v0.1 to v0.2 (bilateral signatures)
- The memex hook (writes to ChromaDB + creates signed commits)
- Atomicity with compensating delete + INCOMPLETE_COMPENSATION (persistent)
- Idempotency with conflict detection (same key, different text → conflict)
- ControlEvent chain verification (monotonic, hash-linked, signed by root)
- Import/export with full identity layer (roundtrip preserves state)
- Corruption detection (truncated JSON, empty files, wrong types, missing fields)
- Fuzzing (unicode, large content, nulls, deep nesting — no crashes)

6 bugs found across 5 adversarial audits, all fixed:
1. Duplicate commit_ids silently ignored → FIXED (load_commits detects)
2. verify_store didn't check ControlEvents → FIXED (verify_identity_layer integrated)
3. cutoff_head existence not checked → FIXED (verify checks DAG membership)
4. idempotency_key with different text → FIXED (conflict detected)
5. Invalid JWK passed verify_self → FIXED (JWK structure validation added)
6. Missing RootAuthority with IdentityRecordV2 → FIXED (verify detects)

Properties demonstrated — protocol (cryptographic core):
  - Integrity of commits (SHA-256 + Ed25519)
  - Cryptographic authorship
  - Key authorization (ControlEvent chain)
  - Non-destructive rotation (cutoff_head + ancestry)
  - Bilateral migration
  - Offline verification
  - Tamper detection
  - Export/import portability

Properties demonstrated — hook/integration (not protocol):
  - Atomicity with compensation (depends on ChromaDB.delete())
  - Idempotency with conflict detection (depends on hook implementation)
  NOTE: these are properties of the MemexAlethechHook adapter, not of the
  alethech protocol itself. They depend on ChromaDB's behavior and the
  hook's lock/compensation logic.

NOT demonstrated:
  - Consistency between ChromaDB and alethech (no distributed transaction)
  - Physical time of commit creation
  - Truth of commit content
  - Global system state offline
  - Equivocation without witness network

Identity spec: rev 3.x APPROVED (semantics closed — cutoff_head defines
causal frontier, not temporal. Alethech does not demonstrate physical time.)

What this means for users:
- If you use the hook today, your commits ARE signed and verifiable.
- If you never rotate keys, none of the open issue affects you.
- If you DO rotate keys, the protocol correctly identifies commits
  signed with revoked keys, and distinguishes:
    * `VALID_HISTORICAL` — commit IS in ancestry(cutoff_head)
    * `NOT_IN_PROVEN_PRE_ROTATION_HISTORY` — commit is NOT in
      ancestry(cutoff_head); the verifier cannot prove it belongs
      to the causal history the rotation closed.
  The verdict is strictly about membership in ancestry(cutoff_head).
  The verifier does NOT claim to prove WHEN the commit was created.
  In particular, it does not claim "this commit was created after
  rotation" — that would require a clock the protocol does not have.

For the full audit material (33 questions + 7 design tests + 5 new
adversarial questions), see the project documentation or request it
from the maintainer.


## quickstart

```bash
pip install alethech
alethech init
alethech migrate --to v0.2  # optional, enables key rotation
```

```python
from memex.direct_store import DirectStore
from alethech.integrations.memex import MemexAlethechHook

# Your existing memex store
direct_store = DirectStore(cfg)

# Wrap it
hook = MemexAlethechHook(
    memex_store=direct_store,
    alethech_store_path="~/.alethech",
)

# add() now writes to BOTH ChromaDB and alethech
hook.add("memory text", user_id="agent")
```

That's it. Every `add()` creates a signed `MemoryCommit` in alethech.

## what you get

| property | how |
|----------|-----|
| Integrity | Each memory has a SHA-256 hash signed with Ed25519 |
| Authorship | Each commit is signed by a `did:alethech:...` identity |
| Offline verification | `alethech verify` works without ChromaDB, Ollama, or network |
| Key rotation | `alethech key rotate` atomically rotates keys, preserves history |
| Migration | `alethech migrate --to v0.2` switches to root-derived identity |
| Portability | `alethech export` packages everything for external audit |

## what you DON'T get (honest)

- The hook doesn't encrypt content. Memories are plaintext in both stores.
- The hook doesn't prevent ChromaDB tampering — it **detects** it.
- The hook doesn't sync retroactively. Pre-hook memories need manual import.

## verify

```bash
alethech verify
```

```
identities: 1 verified, 0 invalid
commits: 42 verified, 0 invalid
HEAD: sha256:... (valid)
result: OK
```

Or from Python:

```python
from alethech.integrations.memex import verify_memex_integrity

report = verify_memex_integrity("~/.alethech")
# {
#   "total_commits": 42,
#   "memex_commits": 41,
#   "valid_signatures": 41,
#   "invalid_signatures": 0,
#   "missing_identity": 0
# }
```

## key rotation

```bash
alethech key rotate
```

Atomically:
1. Revokes current key (with `cutoff_head` = current HEAD)
2. Authorizes new key
3. Replaces signing key on disk

Old commits stay valid (`VALID_HISTORICAL`). New commits use the new key.

## migration (v0.1 → v0.2)

If you started with `alethech init` (v0.1, agent_id derives from operational key):

```bash
alethech migrate --to v0.2
```

Produces a `MigrationRecord` signed bilaterally by the legacy key and the new root. Old commits stay valid with their legacy `agent_id`. New commits use the root-derived `agent_id`.

## export for audit

```bash
alethech export --output ./audit-package
```

Transfer `./audit-package/` to another machine. Verify without ChromaDB:

```bash
alethech verify --path ./audit-package
```

## retroactive import

If you have memories in ChromaDB from before the hook:

```python
from alethech.integrations.memex import MemexAlethechHook

hook = MemexAlethechHook(
    memex_store=direct_store,
    alethech_store_path="~/.alethech",
)

all_memories = direct_store.get_all(user_id="agent", limit=100000)
for memory in all_memories["results"]:
    if hook.active:
        hook._sign_memex_write(
            text=memory["text"],
            user_id=memory.get("user_id", "agent"),
            memex_id=memory["id"],
            metadata=memory.get("metadata", {}),
        )
```

Retroactive commits have current timestamps (when they were signed, not when they were originally written — that's honest).

## performance

The hook adds per `add()`:
- 1 Ed25519 signature (~0.1ms)
- 1 SHA-256 hash (~0.01ms)
- 1 disk write (~1-5ms)

Total: ~2-6ms per `add()`. Negligible vs ChromaDB + Ollama (typically 100-500ms).

## compatibility

| memex | alethech | hook |
|-------|----------|------|
| 0.3.0+ | 0.3.0+ | ✅ full |
| 0.3.0+ | 0.2.0 | ✅ (no hook package) |
| 0.3.0+ | 0.1.0 | ✅ (no migration) |
| pre-0.3.0 | any | ❌ (no `DirectStore`) |

## limitations (rev 1)

1. No automatic retroactive sync (manual import required).
2. No encryption at rest.
3. No proof that ChromaDB has no extra memories (would need periodic checksums).
4. No automatic restore from alethech to ChromaDB.

## spec

Full architecture: [`docs/arquitectura-confianza-agentes.md`](docs/arquitectura-confianza-agentes.md) (rev 2 APPROVED)
Identity layer: [`docs/arquitectura-identidad.md`](docs/arquitectura-identidad.md) (rev 4 APPROVED)
Implementation: [`docs/implementacion-nucleo-minimo.md`](docs/implementacion-nucleo-minimo.md) (rev 3 APPROVED)

## license

MIT.
