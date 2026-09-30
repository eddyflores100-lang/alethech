# Alethech Plugin API

Status: 0.9 development surface.

`alethech-ts/plugin-api.ts` is the stable local-first facade for chat/agent
plugins. It intentionally hides Store layout, DAG traversal, provider bridge
details, and writeback signing internals.

## Lifecycle

```text
.aleth
  -> decrypt locally
  -> createPluginSession(payload)
  -> preparePluginRequest(...)
  -> provider/client outside Alethech core
  -> reviewPluginWriteback(...)
  -> explicit user approval
  -> acceptPluginWriteback(...)
  -> full local verification
  -> reseal updated .aleth locally
```

## API

### `createPluginSession(payload)`

Runs the full portable verifier and returns:

- verified payload;
- verified memory view;
- verified current HEAD.

No context is exposed before verification succeeds.

### `preparePluginRequest(session, provider, userInput, options)`

Supported reference formats:

- `openai`
- `anthropic`
- `local`

This function only prepares data. It performs no network request and manages no
credentials.

Memory is explicitly marked as data rather than provider/system instructions.

### `reviewPluginWriteback(session, responseText)`

Accepts only the strict JSON writeback shape and binds the proposal to the
session's current verified HEAD.

Free-form provider text is not silently promoted into memory.

### `acceptPluginWriteback(session, proposal)`

This is the explicit local trust boundary.

It:

1. verifies the proposal is still bound to current HEAD;
2. creates local Ed25519-signed MemoryCommit objects;
3. advances HEAD linearly;
4. reruns the full portable verifier;
5. returns a new verified plugin session.

A proposal accepted once cannot be replayed against the updated session because
its `source_head` is stale.

## What the plugin API never receives

Provider-facing request objects never include:

- `.aleth` ciphertext;
- passphrase;
- `keys/signing.key`;
- root private key;
- recovery private key;
- raw protocol store files.

The operational signing key remains local to the portable editor/writeback path.

## Network boundary

The Plugin API has no network code.

A provider-specific extension may take a prepared request and send it, but that
network permission belongs to that extension/provider bridge, not Alethech core.
