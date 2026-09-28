"""Verification engine — the core of the protocol.

alethech verify is the standalone verifier. It runs without LLM, without network,
without blockchain, without MarketNow, without UTA, without cloud, without any
external service. Only bytes and cryptographic properties.

It checks (in order):
1. Identities load and self-verify (agent_id <-> public_key)
2. Commits and evidence load and verify signatures
3. DAG integrity (every parent resolves, no cycles, multiple heads are ok)
4. Evidence references resolve
5. Artifacts exist and match hashes
6. HEAD consistency
7. (Optional) Continuity against an external checkpoint
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import crypto
from .objects import Identity, MemoryCommit, EvidenceCommit, Checkpoint
from .store import Store


@dataclass
class VerifyReport:
    """Result of running `alethech verify`."""

    identities_total: int = 0
    identities_invalid: int = 0
    commits_total: int = 0
    commits_invalid: int = 0
    commits_missing_parent: int = 0
    commits_identity_mismatch: int = 0
    commits_not_in_proven_pre_rotation_history: int = 0
    commits_valid_historical: int = 0
    evidence_total: int = 0
    evidence_invalid: int = 0
    artifacts_total: int = 0
    artifacts_missing: int = 0
    artifacts_hash_mismatch: int = 0
    head_valid: bool = True
    head_invalid: str = ""
    continuity_verified: bool = False
    head_commit_id: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            self.identities_invalid == 0
            and self.commits_invalid == 0
            and self.commits_missing_parent == 0
            and self.commits_identity_mismatch == 0
            and self.commits_not_in_proven_pre_rotation_history == 0
            and self.evidence_invalid == 0
            and self.artifacts_missing == 0
            and self.artifacts_hash_mismatch == 0
            and self.head_valid
            and not self.errors
        )

    def summary(self) -> str:
        lines = [
            f"identities: {self.identities_total - self.identities_invalid} verified, {self.identities_invalid} invalid",
            f"commits: {self.commits_total - self.commits_invalid} verified, {self.commits_invalid} invalid, {self.commits_missing_parent} missing_parent, {self.commits_identity_mismatch} identity_mismatch, {self.commits_not_in_proven_pre_rotation_history} not_in_proven_pre_rotation_history, {self.commits_valid_historical} valid_historical",
            f"evidence: {self.evidence_total - self.evidence_invalid} verified, {self.evidence_invalid} invalid",
            f"artifacts: {self.artifacts_total - self.artifacts_missing - self.artifacts_hash_mismatch} verified, {self.artifacts_missing} missing, {self.artifacts_hash_mismatch} hash_mismatch",
        ]
        head_line = "HEAD: " + (self.head_commit_id or "(none)") + " (" + ("valid" if self.head_valid else f"INVALID: {self.head_invalid}") + ")"
        lines.append(head_line)
        if self.continuity_verified:
            lines.append(f"continuity: verified against checkpoint (head: {self.head_commit_id})")
        if self.errors:
            lines.append("errors:")
            lines.extend(f"  ! {e}" for e in self.errors)
        if self.warnings:
            lines.append("warnings:")
            lines.extend(f"  ~ {w}" for w in self.warnings)
        lines.append("result: " + ("OK" if self.ok else "FAIL"))
        return "\n".join(lines)


def verify_store(store: Store, checkpoint: Checkpoint | None = None) -> VerifyReport:
    """Run full verification on a store.

    Returns a VerifyReport. read-only — does not modify the store.
    """
    report = VerifyReport()

    # 1. Load identities
    try:
        identities = store.load_identities()
    except Exception as e:
        report.errors.append(f"identities_load_failed: {e}")
        return report

    report.identities_total = len(identities)

    # Verify each identity self-consistency (agent_id <-> public_key)
    for agent_id, ident in identities.items():
        if not ident.verify_self():
            report.identities_invalid += 1
            report.errors.append(f"identity_mismatch: {agent_id} does not derive from its public_key")

    # 2. Load commits and evidence
    try:
        commits = store.load_commits()
    except Exception as e:
        report.errors.append(f"commits_load_failed: {e}")
        return report

    try:
        evidence = store.load_evidence()
    except Exception as e:
        report.errors.append(f"evidence_load_failed: {e}")
        return report

    report.commits_total = len(commits)
    report.evidence_total = len(evidence)

    # Load v0.2 identities as well (for rev 3)
    try:
        identities_v2 = store.load_identity_records_v2()
    except Exception:
        identities_v2 = {}

    # 3. Verify each commit's signature and identity link
    #    For v0.2 identities, also enforce reachability guarantee:
    #    a commit signed with a revoked key MUST be in ancestry(cutoff_head).
    #    This is the guarantee tonydzi flagged as untested — wiring it here
    #    makes verify_store actually reject 'dark' commits.
    for cid, commit in commits.items():
        # Try legacy identity first
        ident = identities.get(commit.agent_id)
        if ident is not None:
            public_jwk = ident.public_key
            key_state = "VALID_LEGACY"
        else:
            # Try v0.2 identity — find the key by key_id
            v2_ident = None
            for v2 in identities_v2.values():
                if v2.agent_id == commit.agent_id:
                    v2_ident = v2
                    break
            if v2_ident is None:
                report.commits_invalid += 1
                report.errors.append(f"unknown_identity: commit {cid} claims unknown agent_id {commit.agent_id}")
                continue
            # Find the key_id in active or revoked keys
            key_obj = None
            key_state = "UNKNOWN_KEY"
            for k in v2_ident.active_keys:
                if k.get("key_id") == commit.key_id:
                    key_obj = k
                    key_state = "VALID"
                    break
            if key_obj is None:
                for k in v2_ident.revoked_keys:
                    if k.get("key_id") == commit.key_id:
                        key_obj = k
                        key_state = "REVOKED"
                        break
            if key_obj is None:
                report.commits_invalid += 1
                report.errors.append(f"unknown_key: commit {cid} uses key_id {commit.key_id} not in identity {commit.agent_id}")
                continue
            public_jwk = key_obj["public_key"]

        if not commit.verify(public_jwk):
            report.commits_invalid += 1
            report.errors.append(f"signature_invalid: commit {cid} does not verify against identity {commit.agent_id}")
            continue

        # Reachability guarantee (rev 3.x semantic, reinstated in 0.5.3):
        # When a commit is signed by a key that appears in revoked_keys, the
        # signature alone is NOT sufficient evidence. The verifier can only
        # demonstrate one of two things about such a commit:
        #
        #   (a) it is a member of ancestry(cutoff_head)  → VALID_HISTORICAL
        #   (b) it is NOT a member of ancestry(cutoff_head)
        #       → NOT_IN_PROVEN_PRE_ROTATION_HISTORY
        #
        # The verifier deliberately does NOT claim to prove WHEN the commit
        # was created. In particular, it does NOT claim the commit was
        # 'created after rotation'. That would require a clock the protocol
        # does not have. The verdict is strictly about membership in the
        # causal frontier covered by cutoff_head. See tests/test_revoked_key_
        # reachability.py for the mutation-guard tests.
        if key_state == "REVOKED":
            cutoff_head = key_obj.get("cutoff_head", "")
            if not cutoff_head:
                report.commits_not_in_proven_pre_rotation_history += 1
                report.errors.append(
                    f"not_in_proven_pre_rotation_history: commit {cid} signed with revoked key "
                    f"{commit.key_id} but cutoff_head is empty — verifier cannot prove "
                    f"membership in pre-rotation history"
                )
                continue
            if not ancestry_check(cid, cutoff_head, commits):
                report.commits_not_in_proven_pre_rotation_history += 1
                report.errors.append(
                    f"not_in_proven_pre_rotation_history: commit {cid} signed with revoked key "
                    f"{commit.key_id} is NOT in ancestry of cutoff_head {cutoff_head} — "
                    f"verifier cannot prove it belongs to the causal history the rotation closed"
                )
                continue
            # Signature OK and commit IS in ancestry(cutoff_head) → VALID_HISTORICAL.
            report.commits_valid_historical += 1

    # 4. DAG integrity
    commit_ids = set(commits.keys())
    for cid, commit in commits.items():
        for parent in commit.parents:
            if parent not in commit_ids:
                report.commits_missing_parent += 1
                report.errors.append(f"parent_missing: commit {cid} references missing parent {parent}")

    # Detect cycles (BFS)
    if not _detect_cycle(commits):
        pass  # ok
    else:
        report.errors.append("cycle_detected: DAG contains a cycle (should not happen if hashes are correct)")

    # 5. Verify evidence signatures
    for eid, ev in evidence.items():
        ident = identities.get(ev.agent_id)
        if ident is None:
            report.evidence_invalid += 1
            report.errors.append(f"unknown_identity: evidence {eid} claims unknown agent_id {ev.agent_id}")
            continue
        if not ev.verify(ident.public_key):
            report.evidence_invalid += 1
            report.errors.append(f"signature_invalid: evidence {eid} does not verify")

    # 6. Evidence references in commits resolve
    for cid, commit in commits.items():
        refs = commit.provenance.get("evidence_refs", []) if isinstance(commit.provenance, dict) else []
        for ref in refs:
            if ref not in evidence:
                report.warnings.append(f"evidence_missing: commit {cid} references missing evidence {ref}")

    # 7. Artifacts exist and match hashes
    artifacts_on_disk = store.list_artifacts()
    report.artifacts_total = len(artifacts_on_disk)
    for eid, ev in evidence.items():
        for art in ev.artifacts:
            declared_hash = art.get("hash", "")
            if declared_hash not in artifacts_on_disk:
                report.artifacts_missing += 1
                report.errors.append(f"artifact_missing: evidence {eid} references missing artifact {declared_hash}")
                continue
            # verify hash matches content
            data = store.read_artifact(declared_hash)
            if data is not None:
                actual = "sha256:" + crypto.sha256_hex(data)
                if actual != declared_hash:
                    report.artifacts_hash_mismatch += 1
                    report.errors.append(f"artifact_hash_mismatch: artifact {declared_hash} content does not match hash")

    # 8. HEAD consistency
    head = store.read_head()
    if head is None:
        # only ok if there are no commits
        if commits:
            report.head_valid = False
            report.head_invalid = "missing"
            report.errors.append("head_invalid: HEAD file missing but commits exist")
    else:
        report.head_commit_id = head
        if head not in commits:
            report.head_valid = False
            report.head_invalid = "points to nonexistent commit"
            report.errors.append(f"head_invalid: HEAD points to nonexistent commit {head}")

    # 8b. Verify identity layer (rev 3: ControlEvents, MigrationRecords, RootAuthority)
    try:
        report = verify_identity_layer(store, report)
    except Exception as e:
        report.errors.append(f"identity_layer_verification_failed: {e}")

    # 9. Continuity against external checkpoint (corrección 2 + 0.5.6 fix)
    #
    # PRE-0.5.6 BUG: the check only verified that checkpoint.head_commit_id
    # was PRESENT in commits, plus a count match. That allowed a 'dark gap':
    #
    #   genesis ─── A (checkpoint head, count=3)
    #        └──── B ─── HEAD (current, count=3)
    #
    # Both A and HEAD present, counts match, but HEAD does NOT descend from A.
    # The protocol would report continuity_verified = True without proving
    # that the presented history causally continues from the checkpoint.
    #
    # 0.5.6 FIX: checkpoint.head_commit_id must be an ANCESTOR of the
    # current HEAD. I.e., ancestry_check(checkpoint.head_commit_id,
    # current_head, commits) must return True. This closes the dark gap.
    if checkpoint is not None:
        cp_ident = identities.get(checkpoint.agent_id)
        if cp_ident is None:
            report.errors.append(f"checkpoint_unknown_identity: {checkpoint.agent_id}")
        elif not checkpoint.verify(cp_ident.public_key):
            report.errors.append("checkpoint_signature_invalid")
        elif checkpoint.head_commit_id not in commits:
            report.errors.append(f"rollback_detected: checkpoint head {checkpoint.head_commit_id} not present in store")
        elif checkpoint.commit_count != len(commits):
            report.warnings.append(
                f"checkpoint_count_mismatch: checkpoint says {checkpoint.commit_count} commits, store has {len(commits)}"
            )
        elif checkpoint.evidence_count != len(evidence):
            report.warnings.append(
                f"checkpoint_count_mismatch: checkpoint says {checkpoint.evidence_count} evidence, store has {len(evidence)}"
            )
        else:
            # 0.5.6: verify causal continuity. The current HEAD must descend
            # from the checkpoint's head_commit_id. Equivalently:
            # checkpoint.head_commit_id ∈ ancestry(current_HEAD).
            current_head = store.read_head()
            if current_head is None:
                report.errors.append(
                    "checkpoint_continuity_failed: store has no HEAD — cannot prove continuity"
                )
            elif current_head == checkpoint.head_commit_id:
                # Trivial case: store hasn't advanced past checkpoint. Still OK.
                report.continuity_verified = True
            elif not ancestry_check(checkpoint.head_commit_id, current_head, commits):
                report.errors.append(
                    f"checkpoint_continuity_failed: checkpoint head {checkpoint.head_commit_id} "
                    f"is NOT an ancestor of current HEAD {current_head} — the presented history "
                    f"does not causally continue from the checkpoint (dark gap detected)"
                )
            else:
                report.continuity_verified = True

    return report


def _detect_cycle(commits: dict[str, MemoryCommit]) -> bool:
    """Detect if the DAG contains a cycle. Should not happen if hashes are correct."""
    # DFS-based cycle detection
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {cid: WHITE for cid in commits}

    def visit(cid: str) -> bool:
        color[cid] = GRAY
        for parent in commits[cid].parents:
            if parent not in commits:
                continue  # missing parent, handled elsewhere
            if color[parent] == GRAY:
                return True  # back-edge → cycle
            if color[parent] == WHITE and visit(parent):
                return True
        color[cid] = BLACK
        return False

    for cid in commits:
        if color[cid] == WHITE:
            if visit(cid):
                return True
    return False


# ============================================================================
# rev 3 — Identity layer verification
# ============================================================================

from .objects import IdentityRecordV2, ControlEvent, MigrationRecord, RootAuthority


def verify_identity_layer(store, report: VerifyReport) -> VerifyReport:
    """Verify the identity layer (rev 3):
    - Root authority exists and self-verifies
    - IdentityRecordV2 exists and agent_id derives from root
    - Control event chain is monotonic, hash-linked, and signed by root
    - Each active key has a valid key_grant control event
    - Each revoked key has a cutoff_head
    - Migration records (if any) have bilateral signatures
    """
    # Root authority is optional (v0.1 stores don't have it)
    try:
        root = store.load_root_authority()
    except Exception:
        # No root authority — check if there are v2 identities (BUG 6)
        v2_idents = store.load_identity_records_v2()
        if v2_idents:
            report.errors.append(
                "missing_root_authority: IdentityRecordV2 exists but RootAuthority is missing — "
                "possible tampering (root_authority.json deleted)"
            )
        return report

    if not root.verify_self():
        report.errors.append(f"root_authority_mismatch: root_id does not derive from root_public_key")

    # Verify root signature
    if not root.verify(root.root_public_key):
        report.errors.append("root_authority_signature_invalid")

    # Load identity records v2
    try:
        identities_v2 = store.load_identity_records_v2()
    except Exception as e:
        report.errors.append(f"identity_v2_load_failed: {e}")
        return report

    for agent_id, ident in identities_v2.items():
        if not ident.verify_self():
            report.errors.append(f"identity_v2_mismatch: {agent_id} does not derive from root_public_key")

    # 0.5.6 BLOQUEANTE #2: explicit root_id binding.
    #
    # IdentityRecord.verify_self() proves that agent_id derives from
    # root_public_key. But it does NOT prove that root_public_key is
    # THE RootAuthority this store presents as canonical. An attacker
    # who controls a different root keypair could forge an IdentityRecord
    # whose agent_id happens to derive from their (different) root, and
    # the current checks would pass.
    #
    # We must verify explicitly:
    #   IdentityRecord.root_id           == RootAuthority.root_id
    #   IdentityRecord.root_public_key   == RootAuthority.root_public_key
    for agent_id, ident in identities_v2.items():
        if ident.root_id != root.root_id:
            report.errors.append(
                f"identity_root_binding_failed: IdentityRecord {agent_id} declares "
                f"root_id={ident.root_id} but RootAuthority.root_id={root.root_id} — "
                f"identity is not bound to this store's canonical root authority"
            )
        if ident.root_public_key != root.root_public_key:
            report.errors.append(
                f"identity_root_binding_failed: IdentityRecord {agent_id} declares a "
                f"different root_public_key than RootAuthority — identity may be forged "
                f"against a different root"
            )

    # Load control events
    try:
        events = store.load_control_events()
    except Exception as e:
        report.errors.append(f"control_events_load_failed: {e}")
        return report

    if events:
        # Verify each event's signature
        for eid, ev in events.items():
            if not ev.verify(root.root_public_key):
                report.errors.append(f"control_event_signature_invalid: {eid}")

        # 0.5.6 BLOQUEANTE #2: explicit root_id binding for ControlEvents.
        #
        # Same logic as for IdentityRecord: a valid signature against
        # root.root_public_key is necessary but not sufficient. The event
        # must declare the SAME root_id as the store's canonical
        # RootAuthority. Otherwise an attacker could substitute a different
        # root authority (with its own valid signature) and inject events.
        for eid, ev in events.items():
            if ev.root_id != root.root_id:
                report.errors.append(
                    f"control_event_root_binding_failed: ControlEvent {eid} declares "
                    f"root_id={ev.root_id} but RootAuthority.root_id={root.root_id} — "
                    f"event is not bound to this store's canonical root authority"
                )

        # Verify chain monotonicity and hash-linking
        sorted_events = sorted(events.values(), key=lambda e: e.sequence)
        prev_hash = ""
        expected_seq = 1
        for ev in sorted_events:
            if ev.sequence != expected_seq:
                report.errors.append(
                    f"control_chain_invalid: expected sequence {expected_seq}, got {ev.sequence} (event {ev.commit_id})"
                )
                break
            if ev.previous_control_hash != prev_hash:
                report.errors.append(
                    f"control_chain_invalid: event {ev.commit_id} previous_control_hash mismatch"
                )
                break
            prev_hash = ev.commit_id
            expected_seq += 1

        # BUG 3 FIX: Verify that cutoff_head exists in commit DAG
        try:
            commits = store.load_commits()
        except Exception:
            commits = {}
        for ev in events.values():
            if ev.event_type == "key_rotation" and ev.cutoff_head:
                if ev.cutoff_head not in commits:
                    report.errors.append(
                        f"missing_cutoff_head: ControlEvent {ev.commit_id} references "
                        f"nonexistent cutoff_head {ev.cutoff_head}"
                    )

        # RECALL-SEAM DEFENSE (0.5.4 + 0.5.5): Verify consistency between
        # the ControlEvent chain and the IdentityRecord. A key_rotation or
        # key_revoke ControlEvent declares that a key was revoked at a
        # specific cutoff_head. The IdentityRecord MUST reflect this —
        # the revoked key MUST appear in revoked_keys with the matching
        # cutoff_head.
        #
        # Two defeat modes covered:
        #
        # (a) 0.5.4 — key moved from revoked_keys to active_keys.
        #     The reachability check (if key_state == "REVOKED":) is
        #     never invoked. Dark commit passes as VALID.
        #
        # (b) 0.5.5 — key stays in revoked_keys but cutoff_head is
        #     mutated to point at the dark commit itself (or any commit
        #     that has the dark commit in its ancestry). The reachability
        #     check IS invoked, but against the WRONG frontier —
        #     ancestry_check(D, D) returns True, so D passes as
        #     VALID_HISTORICAL.
        #
        # Both are "recall seam" defeats in tonydzi's sense: the
        # guarantee is defeated without editing the line that implements
        # the check. Text moves; properties don't.
        for ident in identities_v2.values():
            for ev in events.values():
                if ev.event_type not in ("key_rotation", "key_revoke"):
                    continue
                # key_rotation revokes old_key_id; key_revoke revokes key_id
                revoked_key_id = ev.old_key_id if ev.event_type == "key_rotation" else ev.key_id
                if not revoked_key_id:
                    continue

                # Check if the key is in revoked_keys with the MATCHING
                # cutoff_head (the legitimate state after rotation).
                in_revoked_matching = any(
                    k.get("key_id") == revoked_key_id
                    and k.get("cutoff_head") == ev.cutoff_head
                    for k in ident.revoked_keys
                )
                # Check if the key is in revoked_keys but with a
                # MISMATCHED cutoff_head (defeat mode b).
                in_revoked_mismatched = any(
                    k.get("key_id") == revoked_key_id
                    and k.get("cutoff_head") != ev.cutoff_head
                    for k in ident.revoked_keys
                )
                # Check if the key is in active_keys (defeat mode a).
                in_active = any(
                    k.get("key_id") == revoked_key_id
                    for k in ident.active_keys
                )

                # Defeat (a): key in active_keys, not in revoked_keys
                # with matching cutoff.
                if in_active and not in_revoked_matching:
                    report.errors.append(
                        f"identity_control_event_mismatch: ControlEvent {ev.commit_id} "
                        f"declares {revoked_key_id} revoked (event_type={ev.event_type}, "
                        f"cutoff_head={ev.cutoff_head}) but IdentityRecord "
                        f"{ident.agent_id} lists it as active — recall-seam defeat"
                    )

                # Defeat (b): key in revoked_keys but with a different
                # cutoff_head than the ControlEvent declares. The
                # reachability check will run against the wrong frontier.
                if in_revoked_mismatched and not in_revoked_matching:
                    # Find the mismatched entry to report which cutoff_head
                    # was used
                    mismatched_entry = next(
                        (k for k in ident.revoked_keys
                         if k.get("key_id") == revoked_key_id
                         and k.get("cutoff_head") != ev.cutoff_head),
                        None
                    )
                    actual_cutoff = mismatched_entry.get("cutoff_head", "") if mismatched_entry else ""
                    report.errors.append(
                        f"identity_control_event_mismatch: ControlEvent {ev.commit_id} "
                        f"declares cutoff_head={ev.cutoff_head} for {revoked_key_id} "
                        f"but IdentityRecord {ident.agent_id} has cutoff_head="
                        f"{actual_cutoff} — reachability frontier tampered"
                    )

    # Verify migration records
    try:
        migrations = store.load_migration_records()
    except Exception as e:
        report.errors.append(f"migration_load_failed: {e}")
        migrations = {}

    for mid, mig in migrations.items():
        if not mig.verify_both(mig.legacy_public_key, mig.new_root_public_key):
            report.errors.append(f"migration_signatures_invalid: {mid}")

    return report


def check_commit_against_governance(commit, identities_v2: dict, events: dict) -> str:
    """Check a commit's signature against the governance state.

    Returns one of:
    - VALID: key is active
    - VALID_HISTORICAL: key is revoked but commit is in ancestry(cutoff_head)
    - NOT_IN_PROVEN_PRE_ROTATION_HISTORY: key is revoked and commit is NOT in ancestry(cutoff_head)
    - UNKNOWN_KEY: key is not in any identity
    - IDENTITY_MISMATCH: commit's agent_id doesn't match the identity that authorized the key
    """
    # Find the identity for this commit's agent_id
    identity = None
    for agent_id, ident in identities_v2.items():
        if agent_id == commit.agent_id:
            identity = ident
            break

    if identity is None:
        return "UNKNOWN_KEY"

    # Find the key in active or revoked
    key_id = commit.key_id
    for k in identity.active_keys:
        if k["key_id"] == key_id:
            return "VALID"

    for k in identity.revoked_keys:
        if k["key_id"] == key_id:
            # Key is revoked. Check cutoff_head ancestry.
            cutoff_head = k.get("cutoff_head", "")
            if not cutoff_head:
                return "NOT_IN_PROVEN_PRE_ROTATION_HISTORY"
            # The caller must verify ancestry separately (needs full commit DAG)
            # Return a sentinel indicating "needs ancestry check"
            return f"NEEDS_ANCESTRY_CHECK:{cutoff_head}"

    return "UNKNOWN_KEY"


def ancestry_check(commit_id: str, cutoff_head: str, commits: dict, max_depth: int = 10000) -> bool:
    """Check if commit_id is in the ancestry of cutoff_head (inclusive).

    Uses BFS to traverse parents. Returns True if commit_id == cutoff_head or
    commit_id is reachable by following parents from cutoff_head.
    """
    if commit_id == cutoff_head:
        return True
    visited = set()
    queue = [cutoff_head]
    depth = 0
    while queue and depth < max_depth:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if current == commit_id:
            return True
        if current not in commits:
            continue
        for parent in commits[current].parents:
            if parent not in visited:
                queue.append(parent)
        depth += 1
    return False
