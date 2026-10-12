"""Regression coverage for signing selection and offline search defaults."""
import sys
import types

import pytest

from alethech.api import Alethech, AlethechError
from alethech import crypto
from alethech.objects import Identity
from alethech.search import create_embedder, TFIDFEmbedder, EnhancedEmbedder, LocalSearch
from alethech.adapters import AdapterError
from click.testing import CliRunner
from alethech.cli import cli


@pytest.mark.parametrize("enhanced,expected", [(False, TFIDFEmbedder), (True, EnhancedEmbedder)])
def test_default_search_does_not_load_neural_model(monkeypatch, enhanced, expected):
    def unexpected_model(*args, **kwargs):
        pytest.fail("offline search attempted to load/download a neural model")
    monkeypatch.setitem(sys.modules, "sentence_transformers", types.SimpleNamespace(SentenceTransformer=unexpected_model))
    embedder = create_embedder(["kubernetes deployment"], enhanced=enhanced)
    assert isinstance(embedder, expected)
    assert any(embedder.embed("kubernetes"))


@pytest.mark.parametrize("operation", ["commit", "evidence"])
def test_unregistered_signing_key_does_not_write(tmp_path, operation):
    client = Alethech.initialize(tmp_path / "store")
    client.store.write_signing_key(crypto.KeyPair.generate())
    before = {str(p.relative_to(client.path)): p.read_bytes() for p in client.path.rglob("*") if p.is_file()}
    with pytest.raises(AlethechError, match="signing key"):
        if operation == "commit":
            client.commit({"fact": "must not persist"})
        else:
            client.evidence(tool="test", input_bytes=b"in", output_bytes=b"out")
    after = {str(p.relative_to(client.path)): p.read_bytes() for p in client.path.rglob("*") if p.is_file()}
    assert after == before


def test_evidence_selects_matching_identity_among_multiple(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    key = crypto.KeyPair.generate()
    identity = Identity(agent_id=crypto.derive_agent_id(key.public_jwk()), public_key=key.public_jwk(), key_id="key-other")
    client.store.write_identity(identity)
    client.store.write_signing_key(key)
    # Force the unrelated identity to appear first, independent of filesystem order.
    original = client.store.load_identities()
    client.store.load_identities = lambda: {**{k: v for k, v in original.items() if k != identity.agent_id}, identity.agent_id: identity}
    ev = client.evidence(tool="test", input_bytes=b"in", output_bytes=b"out")
    assert ev.agent_id == identity.agent_id
    assert ev.key_id == identity.key_id
    assert client.verify().ok


def test_reused_search_sees_new_commits(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    client.commit({"fact": "kubernetes deployment"})
    search = LocalSearch(client.store)
    assert search.recall("kubernetes")
    added = client.commit({"fact": "chocolate recipe"})
    assert search.recall("chocolate")[0].commit_id == added.commit_id
    assert search.stats()["head"] == added.commit_id


def test_cached_search_rejects_tampered_store(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    client.commit({"fact": "kubernetes deployment"})
    search = LocalSearch(client.store)
    assert search.recall("kubernetes")
    client.store.write_head("sha256:" + "0" * 64)
    with pytest.raises(AdapterError, match="unverified"):
        search.recall("kubernetes")


def test_search_result_mutation_does_not_poison_cache(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    client.commit({"fact": "kubernetes deployment"})
    search = LocalSearch(client.store)
    search.recall("kubernetes")[0].content["fact"] = "injected data"
    assert search.recall("kubernetes")[0].content["fact"] == "kubernetes deployment"


@pytest.mark.parametrize("operation", ["commit", "evidence"])
def test_v2_rotated_key_roundtrip(tmp_path, operation):
    client = Alethech.initialize(tmp_path / "store")
    runner = CliRunner()
    for command in [["migrate", "--to", "v0.2"], ["key", "rotate"]]:
        result = runner.invoke(cli, ["--store", str(client.path), *command])
        assert result.exit_code == 0, result.output
    if operation == "commit":
        written = client.commit({"fact": "after rotation"})
    else:
        written = client.evidence(tool="test", input_bytes=b"in", output_bytes=b"out")
    assert written.key_id == "key-002"
    assert client.verify().ok


def test_v2_commit_rejects_unregistered_key(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    result = CliRunner().invoke(cli, ["--store", str(client.path), "migrate", "--to", "v0.2"])
    assert result.exit_code == 0, result.output
    head = client.head
    client.store.write_signing_key(crypto.KeyPair.generate())
    with pytest.raises(AlethechError, match="signing key"):
        client.commit({"fact": "reject"})
    assert client.head == head
