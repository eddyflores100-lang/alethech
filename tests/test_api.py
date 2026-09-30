"""Behavioral tests for the public, Click-free Python API."""
import pytest
from alethech.api import Alethech, AlethechError

def test_initialize_commit_verify_roundtrip(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    genesis = client.head
    commit = client.commit({"fact": "portable API"}, memory_type="semantic", session_id="api-test")
    assert commit.parents == [genesis]
    assert client.head == commit.commit_id
    report = client.verify()
    assert report.ok, report.summary()
    assert report.commits_total == 2

def test_open_existing_store(tmp_path):
    created = Alethech.initialize(tmp_path / "store")
    reopened = Alethech.open(tmp_path / "store")
    assert reopened.head == created.head
    assert reopened.verify().ok

def test_commit_rejects_missing_evidence(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    with pytest.raises(AlethechError, match="evidence_id not found"):
        client.commit({"x": 1}, evidence_refs=["sha256:not-present"])

def test_commit_rejects_invalid_memory_type(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    with pytest.raises(AlethechError, match="unsupported memory_type"):
        client.commit({"x": 1}, memory_type="unknown")

def test_initialize_refuses_nonempty_directory(tmp_path):
    path = tmp_path / "store"
    path.mkdir()
    (path / "foreign.txt").write_text("do not overwrite")
    with pytest.raises(AlethechError, match="directory not empty"):
        Alethech.initialize(path)
