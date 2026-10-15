# Portable memory workflows

## Installation and runtime

Install the whole `alethech` folder through the host's Agent Skills installer.
The public repository supports:

```bash
npx skills add eddyflores100-lang/alethech --skill alethech --global
```

A script-capable host needs Python 3.10+. The helper uses an installed protocol
runtime when available. Otherwise its first invocation creates a private venv in
`~/.cache/alethech-skill/py<major><minor>`, installs the exact `alethech==0.9.5`
release from PyPI, and reruns there. This is executable third-party package
installation; respect the host's existing network and execution permissions.
No global Python packages or IDE settings are changed. Offline provisioning can
install Alethech from a locally supplied wheel and set `ALETHECH_NO_BOOTSTRAP=1`.
Do not set that flag on the first ordinary use unless packages already exist.

If Python or venv support is absent, use the repository's offline viewer; do not
switch to an unverified crypto implementation or request an API key.

## Local storage and trust

Each space has its own encrypted file and local unlock credential. The first
save generates a random credential; no setup question is needed for local use.
On POSIX, managed state directories require 0700 and credentials use 0600.
Windows relies on the account's private directory ACL; use a user-owned directory.
Caller-provided symlink paths are intentionally rejected, including symlinked
parents. Choose a physical directory if your system aliases its home. Internally
created temporary directories resolve OS aliases such as macOS /var to their
physical paths before private file operations.

Full signed history verifies before recall. The last local HEAD is kept outside
the portable file and must be in the presented history's ancestry. Restoring only
an old `.aleth` therefore fails closed. Restoring both file and local checkpoint
can evade that check: the checkpoint is not an independent trust service.
The local checkpoint is not carried to a new device; the first imported history
is a new trust baseline. Pin/check a known HEAD separately when that matters.

Plaintext stores and signing material exist in a restrictive temporary directory
while an operation runs. They are removed on normal completion, not securely
erased. Process termination, swap, filesystem snapshots, malicious software, or
an agent with the same user privileges can expose local secrets. This workflow
does not claim hardware-backed key custody or confinement from a same-user agent.
The portable format's core verifier is unchanged.

## Cloud-folder backup

The user chooses a local directory already synchronized by an installed app such
as Drive for desktop, Dropbox, iCloud Drive, or OneDrive. Alethech performs no
cloud API calls and cannot verify the provider has uploaded or downloaded it.
`copied` means a local filesystem copy, not confirmed remote delivery.

Connect after the first save, entering a password of at least 12 characters once.
Only `<space>.aleth` is copied. The password stays outside the synced folder.
Cloud copies have a password slot; to create a separate recovery-enabled transfer
use `export`. Recovery codes belong in a separate trusted location/password manager.
Do not assume an export recovery code also unlocks a cloud copy.

Before each copy, compare the current file digest with the last published digest.
If another revision appears, preserve it and report `conflict`; local save remains
successful. Import the other file into a fresh space, compare verified handoffs,
then explicitly reconcile useful decisions into the chosen active space. There
is no automatic branch merge and no last-writer-wins overwrite policy.
A local file check cannot provide an atomic distributed compare-and-swap against
simultaneous writes from cloud clients. Use one writer per synced space at a time;
provider conflict copies must be reviewed. Interrupted publication may report a
conflict on retry even if the bytes were successfully copied; inspect the file
instead of forcing an overwrite.

## Transfer and recovery

`export` refuses existing output/recovery paths. It creates a recovery-enabled
ALETH002 with a password chosen through hidden local input. JSON reports paths
and HEAD only. Keep the recovery file in a different directory from the export;
do not send either secret to an AI assistant. Recover through the existing offline
viewer or the protocol's documented recovery API. Import verifies first and only
installs into an empty space; wrong passwords leave no key or memory behind.

A lock left by a killed process is not removed automatically. After confirming no
operation is active, the user may remove the selected space's `.lock` in the
private `locks` directory and retry. Never delete a live lock or all state.

## Memory quality and host automation

Prefer a short, factual handoff over a transcript dump. Record constraints,
confirmed changes, decisions with reasons, test evidence, unresolved questions
and the next action. Preserve user corrections rather than repeating obsolete
claims. Label uncertainty in the text. Use the existing host model to compose
handoffs; Alethech does not call a model itself.

Recall is lexical TF-IDF, explicitly avoiding optional neural embedders even if
other protocol settings enable them. It is not semantic reasoning. Large records
are omitted rather than truncated into misleading fragments. `omitted` includes
unmatched and over-budget entries. A higher explicit byte budget or narrower
saved handoffs may be needed. No promise of provider-side memory or hooks outside
hosts that implement them.
