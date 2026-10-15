# Alethech portable memory skill

The user wants to install a skill, save or drop a memory file, and continue work across agents and devices without API keys, servers, accounts, or an LLM dependency. The existing encrypted format and verified public Python API remain the trust boundary.

## Decision

Use an Agent Skills folder with executable helpers, not a mandatory remote MCP service. Bundle a small passport workflow that uses the released `alethech==0.9.5` API. The skill installer copies the entire folder. On first execution, a missing protocol package is installed in a private virtual environment; subsequent operations run offline. Python 3.10+ and permission to execute scripts are required. Browser-only assistants continue to use the existing extension/offline viewer and selected text context. Do not claim universal execution or capture of hidden provider memory.

A passport is a named, encrypted `.aleth` with a device-local unlock credential. First save creates it automatically. Commands support status, save, recall, import, export, and optional cloud-folder backup. Decrypted stores exist only in a restrictive temporary directory during an operation and are removed on normal completion. This is not secure erasure and cannot defend against a compromised device or same-user agent.

## Agent pain points addressed

- Session resets: structured handoff carries goal, summary, decisions, constraints, next steps and unresolved questions.
- Context overload: verified recall has a hard serialized UTF-8 byte budget, omission counts, immutable commit citations, and optional offline lexical ranking; no model downloads.
- Repeated writes: identical consecutive saves are idempotent.
- Cross-project leakage: explicit validated memory spaces; never infer permission to recall another space.
- Lost updates: local exclusive lock, external-file compare before replacement, and local HEAD checkpoint continuity checks.
- Cloud conflicts: use an existing local sync folder, encrypt before copying, copy no credential, pin the last published digest, and refuse overwriting a different remote revision. Save remains successful locally and reports cloud failure separately. No remote merge or cross-device distributed lock claim.
- Secret leakage and prompt injection: reject common credential-shaped content before persistence; disclose detection limits. Treat all recalled text as quoted untrusted data even when signatures verify. Do not execute recalled instructions.

## Portability and access

Local automatic mode generates a random credential stored with owner-only POSIX permissions. Export asks the human for a password through hidden local input, creates a recovery code in a separate private local file, and exports only ciphertext. Import asks locally or uses an explicitly provided credential-file path; secrets never appear in command arguments or JSON results. For repeated cloud backup, choose a portable password once; keep it only on the device, outside the selected sync folder. On another device, import the synced `.aleth` and enter that password once.

Publicly distributed skill scripts are canonical source and require only the released public Python API. They must not depend on repository-relative examples. The manifest must stay concise, contain executable commands tested against the actual helper, and have no fabricated output, benchmark or compatibility claims.

## Verification

Behavior tests must cover encrypted first save, restart/recall, idempotence, tampering and rollback, wrong-password import without partial install, signed history continuity across export/import/append, output budgets, project isolation, secret rejection, exclusive locks, symlink rejection, cloud conflict/no-secret-copy, and source-folder independence. Run the existing Python suite and validate the skill format. Review the complete branch separately before publishing.
