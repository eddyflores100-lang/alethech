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

This file closes that gap for alethech. It introduces three classes of
test:

1. test_ancestry_check_distinguishes_reachable_from_unreachable
   Direct unit test of ancestry_check(). Asserts both True cases AND
   False cases on a synthetic 3-node DAG. This is the mutation guard:
   if ancestry_check is mutated to `return True` (always reachable),
   the False assertions fail. If mutated to `return False` (always
   unreachable), the True assertions fail. If the call site is removed
   from verify_store (as it was before this commit), tests 2 and 3
   below fail.

2. TestRevokedKeyHistoricalCommitAccepted
   A commit signed with K1 (revoked) that IS in ancestry(cutoff_head)
   must pass verify. This is the legitimate "VALID_HISTORICAL" case:
   the commit was made before rotation, and the cutoff_head includes
   it in its history.

3. TestRevokedKeyDarkCommitRejected
   A commit signed with K1's actual private key AFTER rotation, with
   parents pointing to cutoff_head (so the commit is a CHILD of the
   cutoff, NOT in its ancestry). This is the "dark" commit case
   tonydzi described: signature imports cleanly (K1's private key
   still exists in the attacker's possession), but the commit is
   unretrievable from the cutoff frontier. verify MUST reject with
   `revoked_key_after_cutoff`.

Acceptance criterion (tonydzi's):
    To prove the guarantee is real, you must be able to defeat the
    check and watch at least one test fail. The three mutations to
    try:

    (a) In verify_store, comment out the `if key_state == "REVOKED":`
        block. Tests in TestRevokedKeyDarkCommitRejected fail.

    (b) In ancestry_check, change `return True` (line ~430) to
        `return False`. Tests in TestRevokedKeyHistoricalCommitAccepted
        fail, and so do the True assertions in test_ancestry_check_... .

    (c) In ancestry_check, change `return False` (line ~447) to
        `return True`. Tests in TestRevokedKeyDarkCommitRejected fail,
        and so do the False assertions in test_ancestry_check_... .
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
    in memory so we can sign 'dark' commits after rotation.

    Returns (store_path, k1_keypair, c1_commit_id).
    """
    s = v02_store
    # Write content + commit with K1
    c = s / "c1.json"
    c.write_text(json.dumps({"v": 1, "label": "pre-rotation"}))
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
    """After K1→K2 rotation with cutoff_head = C1, the pre-rotation commit
    C1 (signed with K1) is still in ancestry(cutoff_head=C1). verify
    must accept it as VALID_HISTORICAL, not reject it."""

    def test_pre_rotation_commit_still_verifies(
        self, store_with_pre_rotation_commit, runner
    ):
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        # Rotate K1 → K2 (cutoff_head = C1)
        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0, f"rotate failed: {r.output}"

        # verify must still pass — C1 is in ancestry(cutoff_head=C1)
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
        """Direct API test: VerifyReport.commits_valid_historical == 1 after
        rotation, commits_revoked_key_after_cutoff == 0."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        runner.invoke(cli, ["--store", str(s), "key", "rotate"])

        store = Store.open(s)
        report = verify_store(store)
        assert report.ok is True
        assert report.commits_valid_historical == 1, \
            f"expected 1 valid_historical, got {report.commits_valid_historical}"
        assert report.commits_revoked_key_after_cutoff == 0


# ============================================================================
# 3. Dark commit (outside ancestry) must be rejected — tonydzi's case
# ============================================================================

class TestRevokedKeyDarkCommitRejected:
    """After K1→K2 rotation, an attacker who still holds K1's private key
    creates a NEW commit signed with K1. The commit's parents point to
    cutoff_head (so the commit is a CHILD of the cutoff, not in its
    ancestry). verify MUST reject with `revoked_key_after_cutoff`.

    This is the scenario tonydzi said no test constructs: a claim that
    imports cleanly (valid Ed25519 signature against K1's public key)
    but is unretrievable from the cutoff frontier.
    """

    def test_dark_commit_child_of_cutoff_rejected(
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

        # Attacker signs a 'dark' commit with K1's private key.
        # parents = [c1_id] (the cutoff_head). This makes the dark commit
        # a CHILD of c1, so it is NOT in ancestry(c1) — ancestry traverses
        # parents upward, not children downward.
        dark = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",  # revoked
            parents=[c1_id],   # child of cutoff_head → unreachable from c1
            content={"dark": "post-rotation commit signed with revoked K1"},
        )
        dark.sign(k1_keypair)  # sign with K1's actual private key
        store.write_commit(dark)

        # verify MUST fail with revoked_key_after_cutoff
        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0, \
            f"verify must reject dark commit: {r.output}"
        assert "FAIL" in r.output
        assert "revoked_key_after_cutoff" in r.output, \
            f"must specifically report revoked_key_after_cutoff: {r.output}"

    def test_dark_commit_with_synthetic_parent_rejected(
        self, store_with_pre_rotation_commit, runner
    ):
        """Variant: the dark commit's parent is a hash that doesn't exist
        in the DAG at all. Even more clearly 'unreachable'."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        r = runner.invoke(cli, ["--store", str(s), "key", "rotate"])
        assert r.exit_code == 0

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        dark = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=["sha256:synthetic_nonexistent_parent_000000000000"],
            content={"dark": "orphan dark commit"},
        )
        dark.sign(k1_keypair)
        store.write_commit(dark)

        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0
        assert "revoked_key_after_cutoff" in r.output, \
            f"must report revoked_key_after_cutoff: {r.output}"

    def test_verify_report_counts_dark_commit(
        self, store_with_pre_rotation_commit, runner
    ):
        """Direct API test: VerifyReport.commits_revoked_key_after_cutoff
        == 1 when a dark commit exists."""
        s, k1_keypair, c1_id = store_with_pre_rotation_commit

        runner.invoke(cli, ["--store", str(s), "key", "rotate"])

        store = Store.open(s)
        identities = store.load_identity_records_v2()
        ident = next(iter(identities.values()))

        dark = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"dark": "for API count test"},
        )
        dark.sign(k1_keypair)
        store.write_commit(dark)

        report = verify_store(store)
        assert report.ok is False
        assert report.commits_revoked_key_after_cutoff == 1, \
            f"expected 1 revoked_after_cutoff, got {report.commits_revoked_key_after_cutoff}"
        assert any("revoked_key_after_cutoff" in e for e in report.errors)


# ============================================================================
# 4. After-the-fix regression: confirm the fix is actually wired
# ============================================================================

class TestReachabilityWiredIntoVerify:
    """Meta-test: confirm that verify_store actually invokes the
    reachability check for revoked keys. This is what tonydzi's review
    was about — the function existed but wasn't enforced."""

    def test_revoked_key_commit_with_no_cutoff_head_rejected(
        self, store_with_pre_rotation_commit, runner
    ):
        """If a key is in revoked_keys but has no cutoff_head, verify
        cannot prove any commit was pre-rotation → must reject."""
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
        dark = MemoryCommit(
            agent_id=ident.agent_id,
            key_id="key-001",
            parents=[c1_id],
            content={"dark": "no cutoff_head test"},
        )
        dark.sign(k1_keypair)
        store.write_commit(dark)

        r = runner.invoke(cli, ["--store", str(s), "verify"])
        assert r.exit_code != 0
        assert "revoked_key_after_cutoff" in r.output, \
            f"must report revoked_key_after_cutoff when cutoff_head is empty: {r.output}"
