# alethech.integrations.memex

Write-hook that signs every memex memory with alethech.

## usage

```python
from memex.direct_store import DirectStore
from alethech.integrations.memex import MemexAlethechHook

direct_store = DirectStore(cfg)
hook = MemexAlethechHook(
    memex_store=direct_store,
    alethech_store_path="~/.alethech",
)

# add() writes to BOTH ChromaDB and alethech
hook.add("memory text", user_id="agent")
```

## how it works

Each `add()` call:
1. Calls `memex_store.add()` — writes to ChromaDB as usual
2. Creates a `MemoryCommit` in alethech with:
   - `content.source = "memex.write"`
   - `content.memex_id = <ChromaDB id>`
   - `content.text = <original text>`
3. Signs the commit with the active alethech identity
4. Links to the previous HEAD (forms a DAG)

## passthrough mode

If alethech is not initialized (no `~/.alethech/` directory), the hook silently
skips signing and behaves exactly like the underlying memex store. Zero
behavior change. This makes the integration opt-in: existing memex users
see no difference until they run `alethech init`.

## api

### `MemexAlethechHook(memex_store, alethech_store_path)`

Wrap a memex store with alethech signing.

- `memex_store`: any object with `.add()`, `.search()`, `.get_all()` methods
  (typically `memex.direct_store.DirectStore`)
- `alethech_store_path`: path to the alethech store directory (default `~/.alethech`)

### `hook.add(text, user_id="agent", metadata=None)`

Write a memory to both stores. Returns the same dict as `memex_store.add()`.

### `hook.search(query, user_id="agent", limit=5, filters=None)`

Pass-through to `memex_store.search()`.

### `hook.get_all(user_id="agent", limit=100000)`

Pass-through to `memex_store.get_all()`.

### `hook.active`

`True` if the hook is signing commits. `False` in passthrough mode.

### `verify_memex_integrity(alethech_store_path)`

Verify that all memex-written commits in the alethech store have valid signatures.

Returns:
```python
{
    "total_commits": int,
    "memex_commits": int,
    "valid_signatures": int,
    "invalid_signatures": int,
    "missing_identity": int,
}
```

## examples

### basic usage

```python
from alethech.integrations.memex import MemexAlethechHook

hook = MemexAlethechHook(
    memex_store=direct_store,
    alethech_store_path="~/.alethech",
)

hook.add("the user prefers concise responses")
hook.add("the project uses PostgreSQL")
hook.add("the agent had an error with file X")
```

### verify after writes

```python
from alethech.integrations.memex import verify_memex_integrity

report = verify_memex_integrity("~/.alethech")
assert report["invalid_signatures"] == 0
```

### detect tampering

If someone modifies a commit file:

```python
# Tamper with a commit (simulating an attack)
import json
from pathlib import Path
commit_files = list(Path("~/.alethech/commits").expanduser().glob("*.json"))
target = commit_files[0]
data = json.loads(target.read_text())
data["content"]["text"] = "TAMPERED"
target.write_text(json.dumps(data))

# Now verify
report = verify_memex_integrity("~/.alethech")
assert report["invalid_signatures"] >= 1  # detected
```

## see also

- [INTEGRATION.md](../../../INTEGRATION.md) — full integration guide
- [docs/arquitectura-confianza-agentes.md](../../../docs/arquitectura-confianza-agentes.md) — protocol spec
- [docs/arquitectura-identidad.md](../../../docs/arquitectura-identidad.md) — identity layer spec
