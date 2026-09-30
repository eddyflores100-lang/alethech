# Chat / Provider Adapter Contract

Status: development contract for provider integrations.

## Goal

Alethech must let verified memory move between chats and AI systems without making
the provider itself part of the trust root.

The provider may receive explicit, user-authorized memory context. It must never
need the encrypted `.aleth` container, passphrase, operational private key,
root key, recovery key, or raw protocol store.

## Layers

### 0. Portable core

Input/output: encrypted `.aleth`.

Responsibilities:

- authenticate/decrypt locally;
- verify protocol history;
- append signed MemoryCommit objects locally;
- reseal updated history;
- keep root/recovery authority outside the portable container.

### 1. Verified context adapter

Input: `VerifiedPortableView`.

Output: `alethech-context@1`.

This is the only memory representation a provider bridge should consume.

It contains:

- verified source HEAD;
- selected MemoryCommit IDs;
- memory type;
- timestamp;
- memory content;
- provenance.

It does not contain private keys or raw protocol files.

### 2. Provider bridge

Input: `alethech-chat-envelope@1`.

A bridge MAY send the embedded context to an AI provider only after explicit user
authorization.

A bridge MUST NOT:

- upload the raw `.aleth` file as an implementation shortcut;
- upload or persist the passphrase;
- expose `keys/signing.key`, root key, or recovery key;
- claim provider output is verified Alethech memory;
- auto-sign provider output.

Provider-specific permissions belong in the provider bridge, not in the
permissionless Alethech core extension.

### 3. Writeback proposal

A provider response may be transformed into
`alethech-writeback-proposal@1`.

A proposal is deliberately **unsigned and untrusted**.

Required fields:

- `source_head` — the exact verified HEAD used to produce the provider request;
- one or more proposed memory items;
- memory type;
- content;
- optional source/confidence.

Before accepting a proposal, the local core MUST:

1. validate its schema;
2. confirm `proposal.source_head == current verified HEAD`;
3. require an explicit local acceptance action;
4. create/sign the real MemoryCommit locally;
5. advance HEAD;
6. re-run full verification;
7. reseal a new `.aleth`.

If HEAD changed while the provider was generating a response, the proposal is
stale and MUST NOT be silently applied.

## Why source_head binding matters

Without source-head binding:

1. device A sends context at HEAD H1;
2. device B advances the memory to H2;
3. provider response based on H1 arrives later;
4. blindly applying it on top of H2 can introduce stale or conflicting memory.

Binding the proposal to H1 makes that race explicit. The user or bridge can
re-run the provider request against H2 instead of silently merging stale output.

## Versioned wire shapes

### Chat envelope

```json
{
  "format": "alethech-chat-envelope",
  "version": 1,
  "source_head": "sha256:...",
  "context": {
    "format": "alethech-context",
    "version": 1,
    "source_head": "sha256:...",
    "items": []
  }
}
```

### Writeback proposal

```json
{
  "format": "alethech-writeback-proposal",
  "version": 1,
  "source_head": "sha256:...",
  "items": [
    {
      "memory_type": "semantic",
      "content": {},
      "source": "provider_proposal",
      "confidence": 1.0
    }
  ]
}
```

## Security invariant

Providers can propose information.

Only the local Alethech core can turn a proposal into signed memory.
