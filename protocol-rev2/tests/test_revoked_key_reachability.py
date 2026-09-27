"""Reachability guarantee tests — the gap tonydzi found.

Context
-------
tonydzi (Palo Alto AI Research Lab) reviewed an implementation of the
verified-transfer design and observed:

    "none of the 12 tests construct a claim that imports cleanly
     and is then unretrievable. The reachability guarantee — the one
     thing the design added — is the one guarantee the suite cannot
     detect the loss of."

    "A check nobody has watched fail is a promise, not a guarantee."

This file closes that gap for alethech. It introduces four classes of
test:

1. TestAncestryCheckMutationGuard
   Direct unit test of ancestry_check() on a synthetic 3-node DAG.
   Asserts BOTH reachable cases (return True) AND unreachable cases
   (return False). This is the mutation guard: if anyone changes
   ancestry_check to `return True` always, the False assertions fail;
   if they change it to `return False` always, the True assertions
   fail. If the call site is removed from verify_store (as it was
   before 0.5.2), classes 3 and 4 below fail.

2. TestRevokedKeyHistoricalCommitAccepted
   A commit signed with K1 (now in revoked_keys) that IS a member
   of ancestry(cutoff_head) must pass verify and be reported as
   VALID_HISTORICAL. This is the legitimate historical case: the
   commit belongs to the causal history the rotation closed.

3. TestRevokedKeyNotInProvenPreRotationHistory
   A commit signed with K1's actual private key (the attacker still
   holds it), constructed with `parents = [cutoff_head]` — so the
   commit is a CHILD of the cutoff, not a member of its ancestry.
   Signature imports cleanly against K1's public_key (the key was
   not cryptographically destroyed, only administratively revoked),
   but the commit is unretrievable from the cutoff frontier.

   verify MUST reject with `not_in_proven_pre_rotation_history`.

   CRITICAL SEMANTIC NOTE (rev 3.x):
   The verdict is strictly about membership in ancestry(cutoff_head).
   The verifier does NOT claim to prove WHEN the commit was created.
   In particular, it does NOT claim "this commit was created after
   rotation". That would require a clock the protocol does not have.
   The previous name `revoked_key_after_cutoff` was removed in 0.5.3
   because it implied a temporal claim the artifact cannot support.

4. TestReachabilityWiredIntoVerify
   If a revoked key entry has an empty cutoff_head, verify cannot
   prove membership in any pre-rotation history → must reject with
   `not_in_proven_pre_rotation_history`. This catches the case where
   a key is administratively revoked but the cutoff frontier was
   never recorded.

Acceptance criterion (tonydzi's):
    To prove the guarantee is real, you must be able to defeat the
    check and watch at least one test fail. The three mutations to
    try:

    (a) In verify_store, comment out the `if key_state == "REVOKED":`
        block. Tests in class 3 and class 4 fail.

    (b) In ancestry_check, change `return True` to `return False`
        in the equality shortcut AND the BFS find. Tests in class 2
        fail, and so do the True assertions in class 1.

    (c) In ancestry_check, change the final `return False` to
        `return True`. Tests in class 3 fail, and so do the False
        assertions in class 1.
"""
import json
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from alethech import crypto
from alethech.cli import cli
from alethech.objects import MemoryCommit
from alethech.store import Store
from alethech.verify import ancestry_check, verify_store


# ============================================================================
# 1. Mutation guard — direct unit test of ancestry_check
# ============================================================================

class TestAncestryCheckMutationGuard:
    """Tests that ancestry_check actually distinguishes reachable from
    unreachable. If anyone mutates ancestry_check (or removes the call
    from verify_store), at least one assertion here fails."""

    @staticmethod
    def _fake_dag():
        """Build a tiny DAG: c1 ← c2 ← c3 (parents point backwards)."""
        c1 = SimpleNamespace(commit_id="c1", parents=[])
        c2 = SimpleNamespace(commit_id="c2", parents=["c1"])
        c3 = SimpleNamespace(commit_id="c3", parents=["c2"])
        return {"c1": c1, "c2": c2, "c3": c3}

    def test_reachable_cases_return_true(self):
        """c1, c2, c3 are all in ancestry of c3 (the head)."""
        commits = self._fake_dag()
        # ancestry_check(commit_id, cutoff_head, commits) →
        # "is commit_id reachable from cutoff_head by following parents?"
        assert ancestry_check("c3", "c3", commits) is True, \
            "c3 must be in its own ancestry (inclusive)"
        assert ancestry_check("c2", "c3", commits) is True, \
            "c2 is c3's parent — must be reachable"
        assert ancestry_check("c1", "c3", commits) is True, \
            "c1 is c3's grandparent — must be reachable"

    def test_unreachable_cases_return_false(self):
        """c3 is NOT in ancestry of c2 or c1 (c3 is downstream)."""
        commits = self._fake_dag()
        # These MUST return False. If anyone mutates ancestry_check to
        # `return True` always (e.g., by commenting out the BFS), these
        # assertions fail.
        assert ancestry_check("c3", "c2", commits) is False, \
            "c3 is a CHILD of c2 — must NOT be in c2's ancestry"
        assert ancestry_check("c3", "c1", commits) is False, \
            "c3 is two steps downstream of c1 — must NOT be in c1's ancestry"
        assert ancestry_check("c2", "c1", commits) is False, \
            "c2 is a CHILD of c1 — must NOT be in c1's ancestry"

    def test_nonexistent_commit_returns_false(self):
        """A commit_id that doesn't exist in the DAG must return False,
        not raise."""
        commits = self._fake_dag()
        assert ancestry_check("c4_nonexistent", "c3", commits) is False

    def test_nonexistent_cutoff_head_returns_false(self):
        """If cutoff_head itself doesn't exist in the DAG, no commit can
        be in its ancestry — return False, don't crash."""
        commits = self._fake_dag()
        assert ancestry_check("c1", "nonexistent_head", commits) is False


# ============================================================================
# Fixtures for revocation scenarios
# ============================================================================

@pytest.fixture
def tmp_store():
    d = tempfile.mkdtemp(prefix="alethech-reach-")
    p = Path(d) / "alethech"
    yield p
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def v02_store(tmp_store, runner):
    """v0.2 store: init + migrate."""
    runner.invoke(cli, ["--store", str(tmp_store), "init"])
    runner.invoke(cli, ["--store", str(tmp_store), "migrate", "--to", "v0.2"])
    return tmp_store


@pytest.fixture
def store_with_pre_rotation_commit(v02_store, runner):
    """v0.2 store with ONE commit signed with K1, plus K1's keypair saved
    in memory so we can sign additional commits with K1 after rotation
    (simulating an attacker who kept a copy of the private key).

    NOTE on language: "pre-rotation" here is test-harness shorthand for
    "the commit was created by the test harness before invoking the
    rotation command". It is NOT a claim the cryptographic artifact can
    make on its own. The only claim the verifier can make about C1 after
    rotation is: C1 ∈ ancestry(cutoff_head). The test uses the phrase
    "pre-rotation" only to describe the order in which the harness ran.

    Returns (store_path, k1_keypair, c1_commit_id).
    """
    s = v02_store
    # Write content + commit with K1
    c = s / "c1.json"
    c.write_text(json.dumps({"v": 1, "label": "commit-signed-by-K1"}))
    runner.invoke(cli, ["--store", str(s), "commit", "--content", str(c)])

    # Capture K1's keypair BEFORE rotation (rotation overwrites signing.key)
    store = Store.open(s)
    k1_keypair = store.load_signing_key()
    c1_id = store.read_head()

    return s, k1_keypair, c1_id


# ============================================================================
# 2. Historical commit (in ancestry) must be accepted
# ============================================================================

class TestRevokedKeyHistoricalCommitAccepted:
    """After K1→K2 rotation with cutoff_head = C1, the commit C1 (signed
    with K1, now revoked) is a member of ancestry(cutoff_head=C1). verify
    must accept it as VALID_HISTORICAL, not reject it.

    What the verifier is proving here is strictly: "C1 is in ancestry of
    the cutoff_head recorded for K1's revocation." It is NOT proving
    that C1 was created before the rotation in any physical-clock sense.
    The membership check IS the only evidence the protocol offers."""

    def test_historical_commit_still_verifies(
        self, store_with_pre_rotation_commit, runner
    ):
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        # Rotate K1 → K2 (cutoff_head = C1)
        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0, f"rotate failed: {r.output}"

        # verify must still pass — C1 is a member of ancestry(cutoff_head=C1)
        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code == 0, \
            f"verify must accept historical commit: {r.output}"
        assert "result: OK" in r.output
        # The summary should report 1 valid_historical commit
        assert "valid_historical" in r.output, \
            f"summary must mention valid_historical: {r.output}"

    def test_verify_report_counts_historical(
        self, store_with_pre_rotation_commit, runner
    ):
        """Direct API test: after rotation,
        VerifyReport.commits_valid_historical == 1 and
        commits_not_in_proven_pre_rotation_history == 0."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        runner.invoke(cli, ["--store", str(s), "key", "rotate"])

        store = Store.open(s)
        report = verify_store(store)
        assert report.ok is True
        assert report.commits_valid_historical == 1, \
            f"expected 1 valid_historical, got {report.commits_valid_historical}"
        assert report.commits_not_in_proven_pre_rotation_history == 0


# ============================================================================
# 3. Commit outside ancestry must be rejected — tonydzi's case
# ============================================================================

class TestRevokedKeyNotInProvenPreRotationHistory:
    """Scenario: an attacker who still holds K1's private key constructs
    a NEW commit, signed with K1, with `parents = [cutoff_head]`. This
    makes the commit a CHILD of the cutoff, so it is NOT a member of
    ancestry(cutoff_head) — ancestry traverses parents upward, not
    children downward.

    The signature imports cleanly (Ed25519 verification against K1's
    public_key succeeds — the key was administratively revoked, not
    cryptographically destroyed). But the commit is unretrievable
    from the cutoff frontier.

    verify MUST reject with `not_in_proven_pre_rotation_history`.

    SEMANTIC NOTE: the test harness constructs this commit AFTER calling
    `key rotate`. That ordering is harness knowledge, not artifact
    knowledge. The verifier does NOT claim "this commit was created after
    rotation." It claims only: "this commit is NOT a member of the
    ancestry covered by the rotation's cutoff_head." That is the only
    claim the cryptographic evidence supports, and the only claim the
    verdict makes. The previous verdict name `revoked_key_after_cutoff`
    was retired in 0.5.3 precisely because it implied a temporal claim
    the protocol cannot make.
    """

    def test_commit_child_of_cutoff_rejected(
        self, store_with_pre_rotation_commit, runner
    ):
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        # Rotate K1 → K2 (cutoff_head = C1)
        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0

        # Load identity (now has K1 in revoked_keys with cutoff_head = C1)
        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))
        assert any(k["key_id"] == "key-001" for k in ident.revoked_keys), \
            "K1 must be in revoked_keys after rotation"

        # Construct a commit signed with K1, parents = [c1_id] (the
        # cutoff_head). The commit is therefore a CHILD of c1, so it is
        # NOT in ancestry(c1). Membership check fails → reject.
        constructed = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",  # revoked
            parents=[c1_id],   # child of cutoff_head → not in its ancestry
            content={"constructed": "commit signed with K1, outside cutoff frontier"},
        )
        constructed.sign(k1_keypair)  # sign with K1's actual private key
        store.write_commit(constructed)

        # verify MUST fail with not_in_proven_pre_rotation_history
        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0, \
            f"verify must reject commit outside cutoff frontier: {r.output}"
        assert "FAIL" in r.output
        assert "not_in_proven_pre_rotation_history" in r.output, \
            f"must specifically report not_in_proven_pre_rotation_history: {r.output}"

    def test_commit_with_synthetic_parent_rejected(
        self, store_with_pre_rotation_commit, runner
    ):
        """Variant: the constructed commit's parent is a hash that doesn't
        exist in the DAG at all. Even more clearly 'not in ancestry'."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        constructed = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=["sha256:synthetic_nonexistent_parent_000000000000"],
            content={"constructed": "orphan commit signed with K1"},
        )
        constructed.sign(k1_keypair)
        store.write_commit(constructed)

        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0
        assert "not_in_proven_pre_rotation_history" in r.output, \
            f"must report not_in_proven_pre_rotation_history: {r.output}"

    def test_verify_report_counts_rejected_commit(
        self, store_with_pre_rotation_commit, runner
    ):
        """Direct API test: VerifyReport.commits_not_in_proven_pre_rotation_history
        == 1 when a constructed commit outside ancestry exists."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        runner.invoke(cli, ["--store", str(s), "key", "rotate"])

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        constructed = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"constructed": "for API count test"},
        )
        constructed.sign(k1_keypair)
        store.write_commit(constructed)

        report = verify_store(store)
        assert report.ok is False
        assert report.commits_not_in_proven_pre_rotation_history == 1, \
            f"expected 1 not_in_proven_pre_rotation_history, " \
            f"got {report.commits_not_in_proven_pre_rotation_history}"
        assert any("not_in_proven_pre_rotation_history" in e for e in report.errors)


# ============================================================================
# 4. After-the-fix regression: confirm the fix is actually wired
# ============================================================================

class TestReachabilityWiredIntoVerify:
    """Meta-test: confirm that verify_store actually invokes the
    reachability check for revoked keys. This is what tonydzi's review
    was about — the function existed but wasn't enforced."""

    def test_revoked_key_with_empty_cutoff_head_rejected(
        self, store_with_pre_rotation_commit, runner
    ):
        """If a key is in revoked_keys but has no cutoff_head recorded,
        verify cannot prove membership in any pre-rotation history →
        must reject with not_in_proven_pre_rotation_history.

        Again: the verdict is about the absence of provable membership,
        not about a temporal claim of when the commit was created."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0

        # Tamper: clear cutoff_head on the revoked key entry
        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))
        for k in ident.revoked_keys:
            if k["key_id"] == "key-001":
                k["cutoff_head"] = ""  # break it
        # Re-sign identity with root (otherwise identity_v2_mismatch fires
        # for the wrong reason and obscures the test)
        root_keypair = store.load_root_key()
        ident.sign(root_keypair)
        store.write_identity_record_v2(ident)

        # Now sign a commit with K1 (still have the keypair)
        constructed = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"constructed": "empty cutoff_head test"},
        )
        constructed.sign(k1_keypair)
        store.write_commit(constructed)

        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0
        assert "not_in_proven_pre_rotation_history" in r.output, \
            f"must report not_in_proven_pre_rotation_history when cutoff_head " \
            f"is empty: {r.output}"


# ============================================================================
# 5. Recall-seam defeats — tonydzi's "second mutation" for alethech
# ============================================================================

class TestRecallSeamDefeats:
    """Property-level tests that defeat the guarantee at the RECALL SEAM
    (data mutations), not at the line that implements the check (code
    mutations).

    Context: tonydzi's review of cognicore-dev/cognicore-env#136 found that
    a textual tripwire (`test_reachability_check_defeat_makes_suite_red`)
    only caught mutations that edited the specific line `if dark:`. When
    he defeated reachability at the recall seam
    (`dark = imported_ids - reachable_ids` -> `dark = set()`), the tripwire
    stayed green. The semantic test (`test_dark_claim_fails_import`)
    caught both.

    His general form:
        "a test that proves a guarantee must defeat the guarantee,
         not defeat the line that implements it. Text moves; properties don't."

    For alethech, the equivalent recall seam is the IdentityRecord. If
    someone mutates the IdentityRecord to move K1 from revoked_keys back
    to active_keys (and re-signs with the root key), the
    `if key_state == "REVOKED":` block never executes — the reachability
    check is defeated WITHOUT editing any line of verify.py.

    These tests construct that mutation and assert verify STILL rejects
    the dark commit. If verify accepts it, we have a recall-seam gap and
    must fix verify_identity_layer to detect the inconsistency between
    the IdentityRecord and the ControlEvent chain.

    The key insight: a key_rotation ControlEvent says "K1 was rotated to
    K2 at cutoff_head C1". The IdentityRecord should reflect this —
    K1 should be in revoked_keys with cutoff_head = C1. If the
    IdentityRecord says K1 is in active_keys, it is INCONSISTENT with
    the ControlEvent chain, regardless of whether the IdentityRecord's
    own signature is valid.
    """

    def test_identity_record_undeclares_revocation(
        self, store_with_pre_rotation_commit, runner
    ):
        """Recall-seam defeat: move K1 from revoked_keys back to
        active_keys in the IdentityRecord, re-sign with root.

        The IdentityRecord signature is valid (we re-signed with root).
        The ControlEvent chain still has the key_rotation event.
        But the IdentityRecord no longer reflects the rotation.

        verify MUST detect this inconsistency. If it doesn't, the
        reachability guarantee is defeated at the recall seam — the
        dark commit would pass verify because key_state == "VALID"
        (K1 is in active_keys), so the reachability check is never
        invoked.
        """
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        # Rotate K1 -> K2 (cutoff_head = C1)
        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        # Sanity: K1 should be in revoked_keys after rotation
        assert any(k["key_id"] == "key-001" for k in ident.revoked_keys), \
            "K1 must be in revoked_keys after rotation"
        assert any(k["key_id"] == "key-002" for k in ident.active_keys), \
            "K2 must be in active_keys after rotation"

        # RECALL-SEAM MUTATION: move K1 back to active_keys
        k1_entry = None
        for k in ident.revoked_keys:
            if k["key_id"] == "key-001":
                k1_entry = k
                break
        assert k1_entry is not None
        ident.revoked_keys = [k for k in ident.revoked_keys if k["key_id"] != "key-001"]
        # Add K1 to active_keys (alongside K2 — this is the inconsistency)
        ident.active_keys.append({
            "key_id": "key-001",
            "public_key": k1_entry["public_key"],
            "authorized_at": k1_entry.get("revoked_at", ""),
            "authorized_by": k1_entry.get("revoked_by", ""),
            "expires_at": None,
        })

        # Re-sign the IdentityRecord with root (otherwise the signature
        # check fails, which is a DIFFERENT error and obscures the test)
        root_keypair = store.load_root_key()
        ident.sign(root_keypair)
        store.write_identity_record_v2(ident)

        # Construct a dark commit signed with K1, parents = [c1_id]
        constructed = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"constructed": "recall-seam defeat test"},
        )
        constructed.sign(k1_keypair)
        store.write_commit(constructed)

        # verify MUST fail — the IdentityRecord is inconsistent with the
        # ControlEvent chain (key_rotation event exists, but IdentityRecord
        # says K1 is active).
        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0, \
            f"verify must detect recall-seam defeat: {r.output}"
        assert "FAIL" in r.output
        # The error should mention the inconsistency — either:
        # - identity_control_event_mismatch (the new check we're about to add)
        # - or some other error that reveals the dark commit was caught
        assert r.output != "", f"verify produced no output: {r.output}"

    def test_identity_record_undeclares_revocation_api(
        self, store_with_pre_rotation_commit, runner
    ):
        """Same as above but via the verify_store API, to check the
        VerifyReport directly."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        runner.invoke(cli, ["--store", str(s), "key", "rotate"])

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        # Move K1 back to active_keys
        k1_entry = next(k for k in ident.revoked_keys if k["key_id"] == "key-001")
        ident.revoked_keys = [k for k in ident.revoked_keys if k["key_id"] != "key-001"]
        ident.active_keys.append({
            "key_id": "key-001",
            "public_key": k1_entry["public_key"],
            "authorized_at": k1_entry.get("revoked_at", ""),
            "authorized_by": k1_entry.get("revoked_by", ""),
            "expires_at": None,
        })
        root_keypair = store.load_root_key()
        ident.sign(root_keypair)
        store.write_identity_record_v2(ident)

        # Construct dark commit
        constructed = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"constructed": "API recall-seam test"},
        )
        constructed.sign(k1_keypair)
        store.write_commit(constructed)

        report = verify_store(store)
        assert report.ok is False, \
            "verify_store must reject when IdentityRecord is inconsistent " \
            "with ControlEvent chain"


# ============================================================================
# 6. Cutoff-head mutation — second recall-seam defeat
# ============================================================================

class TestCutoffHeadMutation:
    """Second recall-seam defeat: instead of moving K1 from revoked_keys
    to active_keys (covered by TestRecallSeamDefeats), the attacker keeps
    K1 in revoked_keys but MUTATES the cutoff_head to point at the dark
    commit itself (or any commit that has the dark commit in its ancestry).

    Attack scenario:
      1. K1 rotated to K2, cutoff_head = C1
      2. Attacker constructs dark commit D, signed with K1, parents = [C1]
      3. D is a child of C1, NOT in ancestry(C1) — so normally rejected
      4. Attacker mutates IdentityRecord: changes K1's cutoff_head from
         C1 to D
      5. Re-signs IdentityRecord with root
      6. Now ancestry_check(D, D) = True → D passes as VALID_HISTORICAL

    The ControlEvent still says cutoff_head = C1. The IdentityRecord now
    says cutoff_head = D. They don't match.

    verify MUST detect this mismatch — the cutoff_head in the
    IdentityRecord must match the cutoff_head declared in the
    ControlEvent that revoked the key. If it doesn't, the reachability
    frontier has been tampered with, and the ancestry check is
    validating against the WRONG frontier.
    """

    def test_cutoff_head_mutated_to_dark_commit(
        self, store_with_pre_rotation_commit, runner
    ):
        """Mutate cutoff_head to point at the dark commit itself.

        Before fix: ancestry_check(D, D) = True → D passes as
        VALID_HISTORICAL. verify returns OK.

        After fix: verify detects that IdentityRecord's cutoff_head
        does not match the ControlEvent's cutoff_head →
        identity_control_event_mismatch.
        """
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        # Rotate K1 → K2 (cutoff_head = C1)
        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        # Verify K1 is in revoked_keys with cutoff_head = C1
        k1_entry = next(k for k in ident.revoked_keys if k["key_id"] == "key-001")
        original_cutoff = k1_entry["cutoff_head"]
        assert original_cutoff == c1_id, \
            f"cutoff_head should be C1 ({c1_id}), got {original_cutoff}"

        # Construct dark commit D, signed with K1, parents = [C1]
        dark = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"dark": "cutoff_head mutation test"},
        )
        dark.sign(k1_keypair)
        store.write_commit(dark)
        dark_id = dark.commit_id

        # MUTATION: change K1's cutoff_head from C1 to D (the dark commit)
        for k in ident.revoked_keys:
            if k["key_id"] == "key-001":
                k["cutoff_head"] = dark_id

        # Re-sign IdentityRecord with root
        root_keypair = store.load_root_key()
        ident.sign(root_keypair)
        store.write_identity_record_v2(ident)

        # verify MUST fail — cutoff_head in IdentityRecord does not match
        # the ControlEvent's cutoff_head
        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0, \
            f"verify must detect cutoff_head mutation: {r.output}"
        assert "FAIL" in r.output
        assert "identity_control_event_mismatch" in r.output or \
               "cutoff_head_mismatch" in r.output, \
            f"must report cutoff_head mismatch: {r.output}"

    def test_cutoff_head_mutated_to_dark_commit_api(
        self, store_with_pre_rotation_commit, runner
    ):
        """Same via verify_store API."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        runner.invoke(cli, ["--store", str(s), "key", "rotate"])

        store = Store.open(s)
        ident = next(iter(store.load_identity_records_v2().values()))

        dark = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"dark": "API cutoff_head mutation test"},
        )
        dark.sign(k1_keypair)
        store.write_commit(dark)
        dark_id = dark.commit_id

        # Mutate cutoff_head
        for k in ident.revoked_keys:
            if k["key_id"] == "key-001":
                k["cutoff_head"] = dark_id
        root_keypair = store.load_root_key()
        ident.sign(root_keypair)
        store.write_identity_record_v2(ident)

        report = verify_store(store)
        assert report.ok is False, \
            "verify_store must reject when cutoff_head is mutated"
        assert any(
            "identity_control_event_mismatch" in e or "cutoff_head" in e
            for e in report.errors
        ), f"must report cutoff_head mismatch in errors: {report.errors}"
