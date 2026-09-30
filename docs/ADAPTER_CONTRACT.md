# Alethech Adapter Contract v1 — Draft

Plugins and chat integrations SHOULD consume a **verified memory view**, not the
internal store layout.

Flow:

```
memory.aleth
   -> authenticate/decrypt
   -> Alethech protocol verification
   -> verified memory view
   -> platform adapter
   -> chat / agent context
```

A platform adapter MUST NOT receive memory content if container authentication
or protocol verification fails.

## Neutral view

```json
{
  "format": "alethech-memory-view",
  "version": 1,
  "head": "sha256:...",
  "entries": [
    {
      "commit_id": "sha256:...",
      "agent_id": "did:alethech:...",
      "key_id": "key-001",
      "memory_type": "semantic",
      "session_id": "...",
      "content": {},
      "provenance": {},
      "timestamp": "..."
    }
  ]
}
```

Entries are deterministic and parent-before-child for the history causally
reachable from HEAD. Genesis is omitted from the adapter view.

The timestamp is metadata only. Its presence in the adapter view does not turn
it into a trusted physical-time assertion.

## Adapter responsibilities

An adapter MAY transform entries into a prompt, native memory objects, messages,
or retrieval records. That transformation is platform-specific and outside the
cryptographic protocol.

An adapter MUST preserve the distinction between memory content and provenance,
and MUST NOT present Alethech verification as proof that the content is true.
