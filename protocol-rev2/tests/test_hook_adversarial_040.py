"""Adversarial tests for hook 0.4.0 — the 7 tests from the contract.

A1: ChromaDB ok, alethech fail, delete ok → compensation=succeeded
E1: retry after failure (same key) → 1 memory, 1 commit
E2: retry after success+lost response (same key) → 1 memory, 1 commit
H1: explicit identity selection → correct key; unknown raises
C1: concurrent add() intra-proceso → 2 memories, 2 commits, no corruption
R1: ChromaDB ok, alethech fail, delete fail → INCOMPLETE_COMPENSATION
R2: process dies with INCOMPLETE_COMPENSATION → discover finds it
"""
import json
import shutil
import tempfile
import threading
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from alethech.cli import cli
from alethech.integrations.memex.hook import MemexAlethechHook, CompensatedWriteResult
from alethech.store import Store


class MockMemexStore:
    def __init__(self):
        self.writes = []
        self._fail_on_delete = False

    def add(self, text, user_id="agent", metadata=None):
        memory_id = str(uuid.uuid4())
        self.writes.append({"id": memory_id, "text": text, "user_id": user_id, "metadata": metadata or {}})
        return {"id": memory_id, "text": text}

    def delete(self, memory_id):
        if self._fail_on_delete:
            raise RuntimeError("mock delete failure")
        self.writes = [w for w in self.writes if w["id"] != memory_id]

    def search(self, query, user_id="agent", limit=5, filters=None):
        return [{"id": w["id"], "text": w["text"], "score": 1.0} for w in self.writes[:limit]]

    def get_all(self, user_id="agent", limit=100000):
        return {"results": self.writes[:limit]}


@pytest.fixture
def tmp_alethech():
    d = tempfile.mkdtemp(prefix="alethech-040-")
    p = Path(d) / "alethech"
    runner = CliRunner()
    assert runner.invoke(cli, ["--store", str(p), "init"]).exit_code == 0
    assert runner.invoke(cli, ["--store", str(p), "migrate", "--to", "v0.2"]).exit_code == 0
    yield p
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


# ============ A1 ============

class TestA1_CompensationSucceeded:
    def test_A1_chromadb_ok_alethech_fail_delete_ok(self, tmp_alethech):
        """ChromaDB succeeds, alethech fails, compensating delete succeeds."""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)
        assert hook.active

        with patch.object(hook, "_sign_memex_write", side_effect=RuntimeError("alethech disk full")):
            result = hook.add("test memory A1", user_id="agent")

        assert result["success"] is False
        assert result["compensation_status"] == "succeeded"
        assert len(memex.writes) == 0  # rolled back
        store = Store.open(tmp_alethech)
        memex_commits = [c for c in store.load_commits().values() if c.content.get("source") == "memex.write"]
        assert len(memex_commits) == 0  # no commit created


# ============ E1 ============

class TestE1_RetryAfterFailure:
    def test_E1_retry_same_key_after_failure(self, tmp_alethech):
        """First attempt: alethech fails (compensated). Retry with same key: succeeds."""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        call_count = [0]
        original = hook._sign_memex_write

        def fail_first(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("transient")
            return original(*a, **kw)

        key = "op-E1-test"
        with patch.object(hook, "_sign_memex_write", side_effect=fail_first):
            r1 = hook.add("memory E1", user_id="agent", idempotency_key=key)
            assert r1["success"] is False
            assert r1["compensation_status"] == "succeeded"

            r2 = hook.add("memory E1", user_id="agent", idempotency_key=key)
            assert r2["success"] is True

        assert len(memex.writes) == 1  # first was compensated, second created one
        store = Store.open(tmp_alethech)
        memex_commits = [c for c in store.load_commits().values() if c.content.get("source") == "memex.write"]
        assert len(memex_commits) == 1  # only from retry


# ============ E2 ============

class TestE2_RetryAfterSuccessLostResponse:
    def test_E2_retry_after_success_returns_existing(self, tmp_alethech):
        """First attempt succeeds. Retry with same key returns existing result."""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        key = "op-E2-test"
        r1 = hook.add("memory E2", user_id="agent", idempotency_key=key)
        assert r1["success"] is True
        first_memex_id = r1["id"]
        first_commit_id = r1["alethech_commit_id"]

        # Retry with same key — should return existing, not create new
        r2 = hook.add("memory E2", user_id="agent", idempotency_key=key)
        assert r2["success"] is True
        assert r2["id"] == first_memex_id
        assert r2["alethech_commit_id"] == first_commit_id

        assert len(memex.writes) == 1  # no duplicate
        store = Store.open(tmp_alethech)
        memex_commits = [c for c in store.load_commits().values() if c.content.get("source") == "memex.write"]
        assert len(memex_commits) == 1  # no duplicate


# ============ H1 ============

class TestH1_IdentitySelection:
    def test_H1_unknown_identity_raises(self, tmp_alethech):
        """Passing an identity not in the store should raise ValueError."""
        memex = MockMemexStore()
        with pytest.raises(ValueError, match="identity not in store"):
            MemexAlethechHook(
                memex_store=memex,
                alethech_store_path=tmp_alethech,
                identity="did:alethech:fakefakefakefake",
            )

    def test_H1_default_identity_used_when_none_specified(self, tmp_alethech):
        """Without identity param, the first identity in the store is used."""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)
        assert hook.active
        # Just verify it works — the identity used is the one from migrate
        result = hook.add("test H1", user_id="agent")
        assert result["success"] is True


# ============ C1 ============

class TestC1_ConcurrentAdd:
    def test_C1_two_threads_no_corruption(self, tmp_alethech):
        """Two concurrent add() calls should both succeed without corruption."""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        results = []
        errors = []

        def worker(text):
            try:
                r = hook.add(f"concurrent: {text}", user_id="agent")
                results.append(r)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker, args=("thread-1",))
        t2 = threading.Thread(target=worker, args=("thread-2",))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0, f"errors: {errors}"
        assert len(results) == 2
        assert all(r["success"] for r in results)
        assert len(memex.writes) == 2

        store = Store.open(tmp_alethech)
        memex_commits = [c for c in store.load_commits().values() if c.content.get("source") == "memex.write"]
        assert len(memex_commits) == 2

        # Verify DAG integrity — no corruption
        from alethech.verify import verify_store
        report = verify_store(store)
        assert report.ok, f"verify failed: {report.errors}"


# ============ R1 ============

class TestR1_IncompleteCompensation:
    def test_R1_delete_fails_incomplete_compensation(self, tmp_alethech):
        """ChromaDB ok, alethech fail, delete also fails → INCOMPLETE_COMPENSATION."""
        memex = MockMemexStore()
        memex._fail_on_delete = True  # delete will fail
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        key = "op-R1-test"
        with patch.object(hook, "_sign_memex_write", side_effect=RuntimeError("alethech fail")):
            result = hook.add("memory R1", user_id="agent", idempotency_key=key)

        assert result["success"] is False
        assert result["compensation_status"] == "incomplete"
        assert len(memex.writes) == 1  # memory still in ChromaDB

        store = Store.open(tmp_alethech)
        memex_commits = [c for c in store.load_commits().values() if c.content.get("source") == "memex.write"]
        assert len(memex_commits) == 0  # no commit

        # Verify INCOMPLETE_COMPENSATION was persisted
        comp_dir = tmp_alethech / "incomplete_compensations"
        assert comp_dir.is_dir()
        comp_files = list(comp_dir.glob("*.json"))
        assert len(comp_files) == 1
        record = json.loads(comp_files[0].read_text())
        assert record["status"] == "incomplete"
        assert record["idempotency_key"] == key
        assert record["memex_id"] is not None


# ============ R2 ============

class TestR2_DiscoverIncompletePostRestart:
    def test_R2_discover_incomplete_after_restart(self, tmp_alethech):
        """Process dies with INCOMPLETE_COMPENSATION. New process discovers it."""
        memex = MockMemexStore()
        memex._fail_on_delete = True
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        key = "op-R2-test"
        with patch.object(hook, "_sign_memex_write", side_effect=RuntimeError("alethech fail")):
            hook.add("memory R2", user_id="agent", idempotency_key=key)

        # Simulate process restart: create a new hook instance
        # with a fresh memex store (same alethech store)
        memex2 = MockMemexStore()
        hook2 = MemexAlethechHook(memex_store=memex2, alethech_store_path=tmp_alethech)

        incomplete = hook2.discover_incomplete_compensations()
        assert len(incomplete) == 1
        assert incomplete[0]["idempotency_key"] == key
        assert incomplete[0]["status"] == "incomplete"
        assert incomplete[0]["memex_id"] is not None
