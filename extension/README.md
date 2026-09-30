# Alethech Browser Extension — portable memory client

This is the first local-only drag-and-drop client for the portable `.aleth`
format.

Security boundary:

1. WASM authenticates/decrypts the encrypted envelope locally.
2. TypeScript verifies the complete supported Alethech history before exposing memory.
3. The popup may append a new MemoryCommit only with the portable operational signing key.
4. The updated payload is verified again before WASM reseals a new encrypted .aleth file.
5. Provider-neutral chat context is generated only from the verified memory view.

The extension declares `activeTab` and `scripting` for explicit toolbar capture
and insertion. Its manifest also registers an automatic content script on the
listed URL patterns to display the floating brain. These site matches grant
content-script access independently of temporary `activeTab`; they include chat,
development sites, GitHub routes and localhost. There is no `storage` permission
or global `host_permissions` entry, but this is not a permissionless extension.

Conversation capture occurs on an explicit click. The brain opens an isolated
extension page for review and file creation; passwords are entered only in the
extension interface. File cryptography, history verification, signing and recovery
run locally with WebCrypto and the bundled WASM. No browser storage APIs or upload
services are used. Credentials are cleared after operations, and decrypted state
exists only while the extension interface remains open. Downloads persist at the
user's chosen destination. Sharing context with a provider is an explicit user
choice and follows that provider's privacy policy. See [PRIVACY.md](PRIVACY.md).

Current browser verifier scope is fail-closed and covers legacy V1 identities,
IdentityRecordV2 + RootAuthority, ControlEvent governance, bilateral migrations,
MemoryCommit history, EvidenceCommit provenance, artifact hashes, DAG/HEAD,
signed checkpoints, revoked-key cutoff ancestry, and portable signing-key
binding. Root and recovery private keys are forbidden in portable payloads.

Build:

```bash
cargo install wasm-bindgen-cli --version 0.2.129 --locked
bash scripts/build_extension.sh
```

Then load `extension/dist` as an unpacked Manifest V3 extension.


## Neutral context adapter

After cryptographic verification, `alethech-ts/context-adapter.ts` converts the
verified memory view into a backend-neutral `alethech-context` object. It carries
memory content, provenance, timestamps, commit IDs, and the verified source HEAD,
but never private keys or raw protocol files. Future chat/provider adapters should
consume this verified context rather than parsing `.aleth` directly.


## Continue memory locally

After verification, the popup can append one new signed MemoryCommit to the
current history and download a newly encrypted `.aleth`. The operation uses only
the portable operational signing key already inside the encrypted payload; root
and recovery authority remain separate. The updated payload must pass the full
portable verifier before it can be resealed.

The extension does not overwrite the original file. Each continuation produces a
new downloadable `*-updated.aleth` container.

## Cross-platform filenames

Local filesystem stores use percent-encoded physical filenames such as
`sha256%3A...` and `did%3Aalethech%3A...` so they are valid on Windows,
macOS, and Linux. Signed protocol identifiers remain unchanged, and `.aleth`
containers expose the canonical logical paths with `sha256:` / `did:alethech:`.
Legacy stores that used raw colons remain readable.


## Granular sharing

The extension verifies the complete dropped `.aleth` history locally, but chat
bridges only receive the memories the user explicitly selects in the popup.

The verified global `source_head` is still attached to the outgoing
`alethech-context@1` so writeback remains bound to the exact verified history
used to prepare the provider request.

Selection rules:

- unselected memories are omitted from provider context;
- selected commit IDs must exist in the verified memory view;
- unknown IDs fail closed;
- memory type filters are validated;
- selection never exposes raw protocol files or private keys.


## Passphrase rotation

After a container is unlocked and verified locally, the popup can re-encrypt the
same verified payload under a new passphrase and download a new `.aleth`.

This operation changes only the encryption envelope. It does not create a
MemoryCommit, change HEAD, rotate agent keys, or modify provenance.

The new passphrase is used only in memory for the local reseal operation and is
not persisted by the extension.

## Envelope recovery

The recovery form is available before unlocking. Choose a file, enter its recovery
code, and enter matching new passphrases. The extension authenticates the recovery
slot and verifies the entire portable protocol history before resealing or
creating any download. Recovery preserves the container ID. The optional
"Generate a new recovery code" checkbox rotates the code explicitly; otherwise
the existing code remains usable.

After unlocking, "Create recovery code" adds a recovery slot, upgrading a v1
container to v2. It is disabled when a recovery slot already exists. "Rotate
recovery code" is available only for containers with recovery enabled. Both
require re-entry of the current passphrase. Save generated codes separately from
the encrypted file.

Append, accepted writeback, and passphrase changes preserve v2 envelopes,
container IDs, and existing recovery access. Passphrase changes also require the
current passphrase. Wrong credentials fail before downloading. Every generated
file becomes the current encrypted source within the popup, so subsequent actions
use the latest envelope and history. The extension keeps no credential between
operations; password and recovery input fields are cleared after each operation.
Choosing another file clears verified memory, displayed codes, and credentials;
asynchronous results from the previous selection cannot overwrite the new state.
Files larger than 512 MiB are rejected before reading them into memory.

Rotation affects the newly downloaded file. Earlier copies remain decryptable
with their earlier passphrases or recovery codes; local downloads cannot revoke
existing copies. Closing the popup clears all in-memory state.

## Capture and carry (0.9.2)

The toolbar popup captures the currently loaded conversation after a click,
shows an editable review, creates a new independent signed and verified `.aleth`,
and offers its recovery code separately. Clicking the floating brain also captures
the loaded page and opens an isolated extension page; it does not collect passwords
inside the chat page. A new capture creates its own memory identity and history;
appending to an already opened memory is a separate explicit operation.

The manifest's URL patterns configure where the overlay appears. They do not
certify tested integration with every named platform, and matching desktop IDE
marketing sites does not give access to native IDE applications. Captures depend
on loaded DOM content and provider layout; selected text or paste/import are
fallbacks. The offline single HTML viewer supports import/paste, file creation,
recovery, local verification and context export without the extension. It cannot
read another tab. For desktop clients, use exported text or explicitly configure
the local MCP bridge in [IDE_MEMORY.md](../docs/IDE_MEMORY.md).

See [the full flow](../docs/CHAT_CAPTURE_FLOW.md). Site permission declarations
are defined by the current manifest, including automatic overlay injection.
