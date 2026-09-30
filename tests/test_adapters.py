"""Tests for the verified adapter-facing memory view."""
import pytest

from alethech import Alethech
from alethech.adapters import AdapterError, build_memory_view


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
