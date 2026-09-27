"""Tests for the alethech-memex integration hook.

Uses a mock DirectStore (no ChromaDB/Ollama required) to verify the hook
correctly creates signed MemoryCommits for each memex write.
"""
import json
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from alethech import crypto
from alethech.cli import cli
from alethech.integrations.memex.hook import MemexAlethechHook, verify_memex_integrity
from alethech.objects import MemoryCommit
from alethech.store import Store


# ---------- Mock memex store ----------

class MockMemexStore:
    """Mock of memex.DirectStore — no ChromaDB/Ollama needed.

    Records .add() calls so we can assert the hook called it.
    """

    def __init__(self):
        self.writes: list[dict] = []

    def add(self, text: str, user_id: str = "agent", metadata: dict | None = None) -> dict:
        memory_id = str(uuid.uuid4())
        self.writes.append({
            "id": memory_id,
            "text": text,
            "user_id": user_id,
            "metadata": metadata or {},
        })
        return {"id": memory_id, "text": text}

    def search(self, query: str, user_id: str = "agent", limit: int = 5, filters=None):
        return [{"id": w["id"], "text": w["text"], "score": 1.0} for w in self.writes[:limit]]

    def get_all(self, user_id: str = "agent", limit: int = 100000):
        return {"results": self.writes[:limit]}


# ---------- fixtures ----------

@pytest.fixture
def tmp_paths():
    """Create temp dirs for both alethech and a fake memex store."""
    d = tempfile.mkdtemp(prefix="alethech-memex-")
    alethech_path = Path(d) / "alethech"
    yield alethech_path, MockMemexStore()
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def v01_alethech(tmp_paths, runner):
    """An alethech store initialized with v0.1."""
    alethech_path, _ = tmp_paths
    result = runner.invoke(cli, ["--store", str(alethech_path), "init"])
    assert result.exit_code == 0, result.output
    return tmp_paths


@pytest.fixture
def v02_alethech(v01_alethech, runner):
    """An alethech store migrated to v0.2."""
    alethech_path, _ = v01_alethech
    result = runner.invoke(cli, ["--store", str(alethech_path), "migrate", "--to", "v0.2"])
    assert result.exit_code == 0, result.output
    return v01_alethech


# ---------- Tests ----------

def test_hook_activates_with_v01_alethech(v01_alethech):
    """Hook should activate when alethech v0.1 store exists."""
    alethech_path, memex = v01_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)
    assert hook.active is True


def test_hook_activates_with_v02_alethech(v02_alethech):
    """Hook should activate when alethech v0.2 store exists."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)
    assert hook.active is True


def test_hook_passthrough_when_alethech_missing(tmp_paths):
    """When alethech is not initialized, hook should be inactive (passthrough)."""
    alethech_path, memex = tmp_paths
    # Don't init alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)
    assert hook.active is False


def test_add_writes_to_both_stores(v02_alethech):
    """hook.add() should write to memex AND create an alethech commit."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    result = hook.add("hello world", user_id="agent")

    # memex got the write
    assert len(memex.writes) == 1
    assert memex.writes[0]["text"] == "hello world"

    # alethech got a commit
    store = Store.open(alethech_path)
    commits = store.load_commits()
    # 1 genesis + 1 memex write = 2
    assert len(commits) == 2

    # Find the memex commit
    memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]
    assert len(memex_commits) == 1
    mc = memex_commits[0]
    assert mc.content["text"] == "hello world"
    assert mc.content["user_id"] == "agent"
    assert mc.content["memex_id"] == result["id"]
    assert mc.provenance["source"] == "tool_execution"
    assert mc.provenance["source_id"] == result["id"]


def test_add_returns_result_with_memex_id(v02_alethech):
    """hook.add() should return a result with the memex_id."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    result = hook.add("test text", user_id="agent")
    assert result["id"] is not None
    assert result["text"] == "test text"
    assert result["success"] is True
    assert result["compensation_status"] == "not_needed"


def test_multiple_writes_create_chain(v02_alethech):
    """Multiple hook.add() calls should create a chain of commits."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("first memory")
    hook.add("second memory")
    hook.add("third memory")

    store = Store.open(alethech_path)
    commits = store.load_commits()
    # 1 genesis + 3 writes = 4
    assert len(commits) == 4

    # The 3 memex commits should form a chain (each parent = previous)
    # Build a lookup by commit_id and walk the chain from HEAD
    by_id = {c.commit_id: c for c in commits.values()}
    head = store.read_head()
    chain = []
    current = head
    while current and current in by_id:
        c = by_id[current]
        if c.content.get("source") == "memex.write":
            chain.append(c)
        if not c.parents:
            break
        current = c.parents[0]
    chain.reverse()  # oldest first

    assert len(chain) == 3
    # The first memex commit's parent is genesis
    genesis_commit = [c for c in commits.values() if c.content.get("type") == "genesis"][0]
    assert chain[0].parents == [genesis_commit.commit_id]
    # The second's parent is the first
    assert chain[1].parents == [chain[0].commit_id]
    # The third's parent is the second
    assert chain[2].parents == [chain[1].commit_id]


def test_signed_commits_verify(v02_alethech):
    """All memex-written commits should verify against the identity's public key."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("memory 1")
    hook.add("memory 2")
    hook.add("memory 3")

    store = Store.open(alethech_path)
    identities_v2 = store.load_identity_records_v2()
    ident = next(iter(identities_v2.values()))
    # Get the active key's public key
    active = ident.active_keys[0]
    pub_jwk = active["public_key"]

    commits = store.load_commits()
    memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]
    for c in memex_commits:
        assert c.verify(pub_jwk) is True, f"commit {c.commit_id} failed to verify"


def test_tamper_memex_doesnt_affect_alethech(v02_alethech):
    """Tampering with memex's stored memory should NOT affect alethech commits."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("original text")

    # Tamper with memex's stored memory
    memex.writes[0]["text"] = "TAMPERED"

    # Alethech commit should still have the original text
    store = Store.open(alethech_path)
    commits = store.load_commits()
    memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]
    assert memex_commits[0].content["text"] == "original text"


def test_passthrough_when_alethech_missing(tmp_paths):
    """When alethech is not initialized, hook.add() should still write to memex."""
    alethech_path, memex = tmp_paths
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    result = hook.add("test")

    assert len(memex.writes) == 1
    assert memex.writes[0]["text"] == "test"
    # No alethech commits should exist
    assert not alethech_path.exists()


def test_search_passes_through(v02_alethech):
    """hook.search() should pass through to memex.search()."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("hello world")
    results = hook.search("hello")
    assert len(results) == 1
    assert results[0]["text"] == "hello world"


def test_verify_memex_integrity(v02_alethech):
    """verify_memex_integrity should report correct counts."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("memory 1")
    hook.add("memory 2")

    report = verify_memex_integrity(alethech_path)
    # 1 genesis + 2 memex writes = 3 total commits
    assert report["total_commits"] == 3
    assert report["memex_commits"] == 2
    assert report["valid_signatures"] == 2
    assert report["invalid_signatures"] == 0
    assert report["missing_identity"] == 0


def test_verify_memex_integrity_detects_tamper(v02_alethech):
    """If we tamper with a commit's content, verify_memex_integrity should detect it."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("original memory")

    # Tamper with the commit file
    store = Store.open(alethech_path)
    commits = store.load_commits()
    memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]
    target = memex_commits[0]
    target.content["text"] = "TAMPERED"
    store.write_commit(target)

    report = verify_memex_integrity(alethech_path)
    assert report["invalid_signatures"] >= 1


def test_get_all_passes_through(v02_alethech):
    """hook.get_all() should pass through to memex.get_all()."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("memory 1")
    hook.add("memory 2")

    result = hook.get_all()
    assert len(result["results"]) == 2


def test_hook_supports_key_rotation(v02_alethech, runner):
    """After key rotation, hook should sign new commits with the new key."""
    alethech_path, memex = v02_alethech
    hook = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)

    hook.add("before rotation")

    # Rotate
    runner.invoke(cli, ["--store", str(alethech_path), "key", "rotate"])

    # Re-init hook to pick up new key
    hook2 = MemexAlethechHook(memex_store=memex, alethech_store_path=alethech_path)
    hook2.add("after rotation")

    store = Store.open(alethech_path)
    commits = store.load_commits()
    memex_commits = sorted(
        [c for c in commits.values() if c.content.get("source") == "memex.write"],
        key=lambda c: c.timestamp,
    )
    assert len(memex_commits) == 2
    # First commit should be signed with key-001
    assert memex_commits[0].key_id == "key-001"
    # Second commit should be signed with key-002
    assert memex_commits[1].key_id == "key-002"
