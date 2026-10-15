# Integration: alethech + private memory vault — a two-layer memory that survives resets

> Let the signed chain carry pointers and proofs, the encrypted vault carry context — and every session begin by proving both agree.
>
> © 2026 AliceLabs LLC. MIT License.

## STATUS — read this first

**Running in production since 2026-10-09. Chain state at time of writing: 86 commits verified, 0 invalid; latest vault sha256 bound by a signed pointer commit. The pattern has survived 3+ full sandbox resets with zero memory loss — full task history (230+ tasks), pending items, lessons, and a 258 KB worklog were recovered in under 2 minutes from cold state.**

What this pattern adds on top of the protocol:
- A **sectioned encrypted vault** (Fernet) for private context the chain must never carry
- A **session-start reload ritual** that rebuilds full working state from cold in minutes
- A **session-end writeback ritual** (one command, `memory_writeback.sh`) that refuses to write anything when the chain is not verifiably OK
- A **master memory document** — a single canonical file that makes agent continuity independent of any conversation window

## Why

An agent whose context lives only in a conversation window loses everything on every reset, compaction, or crash. An agent whose context lives only in the signed chain faces the opposite problem: the chain is plaintext by design (secrets-free, auditable), so private context does not belong there. The fix is two layers with different jobs, bound by pointer commits:

| Layer | Where | Carries | Failure semantics |
|---|---|---|---|
| 1 — chain (alethech) | `.alethech/` (plaintext, signed) | facts, milestones, lessons, vault sha256 pointers | `alethech verify` fail-closed: any invalid commit = do not trust, report |
| 2 — vault (Fernet) | `.alethech-private/` (encrypted, 0600) | task history, user profile, lessons, pending items, worklog snapshot | `vault.py status` fail-closed: open failure or pointer mismatch = do not trust, report |

The pointer commits (`{"type":"memory-vault","vault_sha256":...}`) make the vault tamper-evident too: if the vault's current sha256 does not match the newest pointer in the chain, someone rewrote context out-of-band.

## The sectioned vault

`examples/memory_vault.py` maintains named sections. Use whichever fit your agent:

| Section | Typical content |
|---|---|
| `user_profile` | identity, preferences, language, operating style |
| `environment` | host facts, installed tooling, known-good paths |
| `projects` | repo layout, deploy targets, live URLs |
| `key_artifacts` | where artifacts live (paths only — never the secrets themselves) |
| `lessons_rules` | operational lessons as durable rules |
| `pending_items` | the open work queue, categorized |
| `task_history` | one entry per completed task (id, title, summary, timestamp) |
| `worklog_snapshot` | full text of the worklog, refreshed by `sync` |

## Session-start ritual (reload from cold)

Run in this order; stop and report if any step fails closed:

```bash
alethech verify                                # 1. chain intact?
python3 examples/memory_vault.py status        # 2. vault opens + pointer matches?
python3 examples/memory_vault.py read pending_items   # 3. recover the open queue
python3 examples/memory_recall.py --last 5     # 4. newest durable facts
```

Plus one human-readable file: keep a **master memory document** in the project root — a single markdown file with the reload protocol, account/credential *locations* (never values), open threads, golden rules, and one-liners for recent tasks. After any reset, read it first; it is the index into everything else. 2 minutes to full context.

## Session-end ritual (close the loop)

```bash
# during the session, after each task:
python3 examples/memory_vault.py add --id task-42 --title "..." --summary "..."

# at the end:
alethech commit --content lesson.json --type procedural --session "$SESSION_ID"
VAULT_SYNC_CMD="python3 examples/memory_vault.py sync" bash examples/memory_writeback.sh
```

`memory_writeback.sh` runs vault sync → signed pointer commit → `alethech verify`, and **aborts without writing anything** if the chain is not verifiably OK. Nothing is stored unless a commit hash is printed: do not invent success.

## Failure semantics

- `alethech verify` reports any `identity_mismatch`, `missing_parent`, or hash failure → the chain is tampered or corrupted: do not trust it, fall back to the vault's worklog snapshot, tell the operator.
- `memory_vault.py status` fails to open → wrong key or corruption: do not trust the vault, report it. A vault that fails to open is **not** an empty vault.
- Pointer mismatch (vault sha ≠ newest chain pointer) → context was rewritten out-of-band: diff before trusting.
- Empty recall result → absence of evidence, not evidence of absence.

## Anti-patterns

- **Secrets in either layer.** Tokens, passwords, and private keys go in chmod-600 files outside the chain and the vault. The vault carries context, not credentials.
- **Rewriting history.** Both layers are append-only. To correct a fact, write the correction; superseded records stay.
- **Paraphrased retrieval.** Quote the chain verbatim; similarity is not confidence.
- **Trusting a green check you didn't run.** Verify with the exact binaries and paths your agent session uses.

## Production evidence

This pattern ran through 3+ complete sandbox rebuilds (workspace wiped, venv wiped, only the vault, chain, and master memory document persisted). Each time, the agent recovered identity, rules, open threads, task history, and the exact state of in-flight work — including a multi-day malware takedown investigation (13 venues, RDAP evidence chain) that continued seamlessly across resets and ended in a confirmed registrar suspension. The memory layer never lost a task, a credential location, or a lesson.

## Files in this repo

- `examples/memory_vault.py` — the sectioned encrypted vault (pluggable step-1 for writeback)
- `examples/memory_recall.py` — verbatim chain reader (`--last/--type/--search`)
- `examples/memory_writeback.sh` — the one-command close-the-loop ritual
- `examples/memory_audit_seal.sh` — artifact integrity seal/audit (see `INTEGRATION-AUDIT.md`)
- `INTEGRATION-VIGIL.md` — continuous fail-closed watchdog over the same two layers
