# Integration: alethech + memex

> Make every memex memory cryptographically verifiable — without changing memex.

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
