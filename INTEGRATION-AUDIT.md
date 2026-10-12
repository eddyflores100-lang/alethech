# Integration: alethech + audit/snapshot/drill — durability for agent memory

> Seal your memory artifacts into the chain, snapshot them to a private remote with zero secret leakage, and prove your restore plan works — measured, not promised.
>
> © 2026 AliceLabs LLC. Todos los derechos reservados.

## STATUS — read this first

**Running in production since 2026-10-12. Live drill result: full cold restore (2 clones + fresh venv + install + verify + audit + brief) completed and verified in 42 seconds, zero secret leakage, on a workspace that had actually lost a session to a platform reset.**

What this pattern adds on top of [INTEGRATION-VIGIL.md](INTEGRATION-VIGIL.md):
- **Layer 3 — artifact integrity**: a sha256 manifest of the files your memory treats as ground truth (lessons, cards, index, worklog), *sealed as a signed commit in the chain itself*, auditable offline with one command
- **Layer 4 — durability**: a post-writeback snapshot push to a private remote built as an **orphan commit from a temporary git index** — your history (which may track secrets you forgot about) never leaves the machine
- **Layer 5 — recovery**: a restore drill that treats "we could restore" as a claim to be *tested end-to-end on a schedule*

## Why

Vigil proves the *chain* is intact. But an agent's real memory state is bigger than the chain: the unsealed files around it (indexes, distilled cards, lesson logs) can silently drift, and the whole workspace can vanish (platform resets, disk loss, rotated sandboxes). We lived it: an entire session's work was erased between two runs while the chain survived untouched. Integrity of artifacts, durability across platforms, and a *measured* recovery path are three different problems — this pattern solves all three with zero external AI tokens.

## The three layers

### 1. Artifact integrity: `seal` / `audit`

Hash every file your memory treats as ground truth and commit the manifest to the chain as a semantic commit (`content.type = "artifact-manifest"`). Then audit offline at any time:

```
[OK     ] .agent/LESSONS.md
[DRIFT  ] .agent/MEMORY_CARDS.md      ← changed since seal (legit? re-seal. else investigate)
[MISSING] worklog.md
```

Design rules learned the hard way:
- The manifest **must not include itself** (self-referential hash = perpetual false DRIFT)
- The chain's `HEAD` **must not be sealed** (the seal commit itself moves it — chain integrity is `verify`'s job)
- Clean separation: **`verify` = integrity of the CHAIN · `audit` = integrity of the ARTIFACTS**

Exit codes are vigil-ready: `0` clean, `2` anomalies.

### 2. Durable snapshot: orphan-commit push

After every writeback, push a snapshot of the memory workspace to a private remote — built as an **orphan commit from a temporary `GIT_INDEX_FILE`** containing only whitelisted paths, then `push --force`:

- What goes up: worklog, memory artifacts, scripts, the chain (`commits/` + `identities/` + `HEAD`)
- What never goes up: credentials, signing keys, local backups — and **the git history itself** (our workspace history had been silently tracking `.secrets/*` and signing keys for weeks; the orphan approach makes that leak class structurally impossible)
- Belt and braces: the script aborts if the temp index ever contains a sensitive path

Recovery after a catastrophic reset is then: `git clone` the snapshot + `pip install` the CLI → verify. Two commands, because the snapshot carries everything.

### 3. Restore drill: measure the recovery, don't assume it

A backup that has never been restored is a hypothesis. The drill reproduces the worst case in a temp dir — clone snapshot, clone the public mirror, fresh venv, `pip install`, `verify`, `audit`, `brief` — and asserts zero secret leakage in the clone. Our production result: **42 seconds, cold**. Schedule it (we run it weekly via `memory_vigil.sh --drill`) so rot in the snapshot remote is caught while it is cheap to fix.

### Bonus: GitHub Actions self-verification, zero secrets

The snapshot repo can verify *itself* on a schedule: checkout → install the CLI from the public mirror → `verify` the committed chain → `audit` the sealed artifacts → assert no sensitive paths in the tree. Verify and audit only need public data, so the workflow needs **no repository secrets at all**. A red job means corruption or a leak — check immediately.

## Minimal usage

```bash
# seal artifacts into the chain (after legit work, inside your writeback)
python scripts/memory_audit.py seal

# offline integrity check — daily, fail-closed
python scripts/memory_audit.py audit          # exit 0 clean / 2 anomalies

# weekly drill (see repo: memory_vigil_drill.sh)
GH_TOKEN=... bash scripts/memory_vigil.sh --drill
```

See [examples/memory_audit_seal.sh](examples/memory_audit_seal.sh) for a self-contained seal+audit loop.

## Production notes (2026-10)

- The chain survived a platform reset that erased everything else in the workspace; the *session*, not the chain, is the unit of loss — hence snapshot-per-writeback.
- `git add pathA pathB` with one nonexistent path fails **entirely** and `|| true` masks it: multi-path adds in scripts get separate steps or no swallowing.
- Untrack secrets from the *live* branch (`git rm --cached --ignore-unmatch .secrets .alethech/keys` + `.gitignore`) so future platform auto-commits stay clean; fixing history is optional once the orphan push guarantees it never travels.
