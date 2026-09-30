"""Tests for the verified adapter-facing memory view."""
import pytest

from alethech import Alethech
from alethech.adapters import (
    AdapterError,
    accept_writeback_proposal,
    build_memory_view,
    create_chat_envelope,
    validate_writeback_proposal,
)


def test_memory_view_is_verified_and_causally_ordered(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    first = agent.commit({"fact": "first"}, session_id="s1")
    second = agent.commit({"fact": "second"}, session_id="s2")

    view = build_memory_view(agent.store)

    assert view.head == second.commit_id
    assert [e.commit_id for e in view.entries] == [first.commit_id, second.commit_id]
    assert [e.content["fact"] for e in view.entries] == ["first", "second"]
    assert view.to_dict()["format"] == "alethech-memory-view"
    assert view.to_dict()["version"] == 1


def test_memory_view_never_exposes_unverified_store(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    agent.commit({"fact": "secret"})
    (agent.path / "HEAD").write_text("sha256:not-a-real-head", encoding="utf-8")

    with pytest.raises(AdapterError, match="unverified memory"):
        build_memory_view(agent.store)


def test_drop_file_to_verified_context(tmp_path):
    source = Alethech.initialize(tmp_path / "source")
    source.commit({"fact": "drag and drop"})
    container = source.seal(tmp_path / "memory.aleth", "drop-secret")

    context = Alethech.drop_context(container, "drop-secret")

    assert context["format"] == "alethech-memory-view"
    assert context["head"] == source.head
    assert [e["content"] for e in context["entries"]] == [{"fact": "drag and drop"}]


def test_drop_file_wrong_passphrase_exposes_no_context(tmp_path):
    source = Alethech.initialize(tmp_path / "source")
    container = source.seal(tmp_path / "memory.aleth", "drop-secret")

    with pytest.raises(Exception, match="authentication failed"):
        Alethech.drop_context(container, "wrong")


def test_python_chat_envelope_and_local_writeback(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    agent.commit({"fact": "seed"})
    before = build_memory_view(agent.store)
    envelope = create_chat_envelope(before)

    assert envelope["format"] == "alethech-chat-envelope"
    assert envelope["version"] == 1
    assert envelope["source_head"] == before.head
    assert envelope["context"]["format"] == "alethech-context"
    assert envelope["context"]["source_head"] == before.head
    assert len(envelope["context"]["items"]) == 1

    proposal = {
        "format": "alethech-writeback-proposal",
        "version": 1,
        "source_head": before.head,
        "items": [
            {
                "memory_type": "semantic",
                "content": {"provider_fact": "gamma"},
                "source": "provider_proposal",
                "confidence": 0.7,
            },
            {
                "memory_type": "episodic",
                "content": {"provider_event": "delta"},
                "source": "provider_proposal",
                "confidence": 0.8,
            },
        ],
    }
    created = accept_writeback_proposal(agent.store, proposal)
    assert len(created) == 2

    after = build_memory_view(agent.store)
    assert after.head == created[-1]
    commits = agent.store.load_commits()
    first, second = commits[created[0]], commits[created[1]]
    assert first.parents == [before.head]
    assert second.parents == [created[0]]
    assert first.provenance["source"] == "provider_proposal"
    assert first.provenance["confidence"] == 0.7
    assert second.provenance["confidence"] == 0.8
    assert agent.verify().ok


def test_python_writeback_rejects_stale_and_invalid_without_writing(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    before = agent.head
    commits_before = set(agent.store.load_commits())

    stale = {
        "format": "alethech-writeback-proposal",
        "version": 1,
        "source_head": "sha256:" + "0" * 64,
        "items": [{"memory_type": "semantic", "content": {"stale": True}}],
    }
    with pytest.raises(AdapterError, match="stale writeback proposal"):
        accept_writeback_proposal(agent.store, stale)
    assert set(agent.store.load_commits()) == commits_before
    assert agent.head == before

    invalid = {
        "format": "alethech-writeback-proposal",
        "version": 1,
        "source_head": before,
        "items": [{"memory_type": "system", "content": {"bad": True}}],
    }
    with pytest.raises(AdapterError, match="invalid writeback memory_type"):
        validate_writeback_proposal(invalid)
    assert set(agent.store.load_commits()) == commits_before
    assert agent.head == before


def test_commit_validates_provider_provenance_fields(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    with pytest.raises(Exception, match="confidence must be between 0 and 1"):
        agent.commit({"x": 1}, confidence=1.5)
    with pytest.raises(Exception, match="source must be a non-empty string"):
        agent.commit({"x": 1}, source="")
