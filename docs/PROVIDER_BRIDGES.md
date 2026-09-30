# Provider Bridges

Status: reference bridge layer for 0.9 development.

## Purpose

Provider bridges convert already-verified Alethech memory into request payloads
for external chat/agent clients. They do **not** perform network requests and do
not manage provider API keys.

The trust boundary is:

```
.aleth
  -> local decrypt
  -> full Alethech verification
  -> alethech-context@1
  -> provider bridge request payload
  -> external provider
  -> unsigned writeback proposal
  -> explicit local acceptance
  -> local Ed25519 signing
  -> full verification
  -> resealed .aleth
```

The external provider never becomes part of the Alethech trust root.

## Reference bridges

`alethech-ts/provider-bridges.ts` currently exposes:

- `toOpenAICompatibleRequest()`
- `toAnthropicCompatibleRequest()`
- `toLocalAgentRequest()`
- `writebackProposalFromProviderJson()`

These functions only transform data. They make no HTTP requests.

## Prompt-injection boundary

Verified memory can still contain malicious text. Cryptographic verification
proves provenance/integrity, not semantic safety.

Every provider request therefore contains an explicit policy that the
`ALETHECH_CONTEXT` block is **data**, not system/developer instructions.
Bridges must not silently promote remembered text into higher-priority
instructions.

This is not a complete prompt-injection defense; it is a required boundary
between verified memory and provider instructions.

## Writeback

Provider output is never directly accepted as memory.

The reference bridge only accepts strict JSON:

```json
{
  "alethech_writeback": [
    {
      "memory_type": "semantic",
      "content": {"fact": "example"},
      "source": "provider_proposal",
      "confidence": 0.8
    }
  ]
}
```

Free-form text is rejected. The resulting
`alethech-writeback-proposal@1` remains unsigned and untrusted until explicit
local acceptance through `acceptWritebackProposal()`.

The proposal is bound to the verified `source_head`; stale proposals are
rejected rather than silently merged onto a newer history.

## Non-goals

The bridge layer does not:

- upload `.aleth`;
- expose the passphrase;
- expose operational/root/recovery private keys;
- make provider API calls;
- persist provider credentials;
- auto-accept provider output;
- claim that provider-generated content is true.

Provider-specific network clients belong outside the portable Alethech core.
