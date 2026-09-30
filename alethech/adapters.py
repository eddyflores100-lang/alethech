"""Verified neutral memory view for chat/agent adapters.

Adapters consume this module instead of depending on Store layout or DAG details.
No memory content is returned unless the underlying store verifies successfully.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .store import Store
from .verify import verify_store


class AdapterError(Exception):
    """The store cannot safely be exposed to an adapter."""


@dataclass(frozen=True)
class MemoryEntry:
    commit_id: str
    agent_id: str
    key_id: str
    memory_type: str
    session_id: str
    content: dict[str, Any]
    provenance: dict[str, Any]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "memory_type": self.memory_type,
            "session_id": self.session_id,
            "content": self.content,
            "provenance": self.provenance,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class VerifiedMemoryView:
    """Backend-neutral, verified view of the history reachable from HEAD."""

    head: str
    entries: tuple[MemoryEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "alethech-memory-view",
            "version": 1,
            "head": self.head,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def _causal_order(head: str, commits: dict) -> list[str]:
    """Deterministic parent-before-child order for the history reachable from HEAD."""
    ordered: list[str] = []
    seen: set[str] = set()
    stack: list[tuple[str, bool]] = [(head, False)]

    while stack:
        commit_id, expanded = stack.pop()
        if expanded:
            if commit_id not in seen:
                seen.add(commit_id)
                ordered.append(commit_id)
            continue
        if commit_id in seen:
            continue
        commit = commits.get(commit_id)
        if commit is None:
            raise AdapterError(f"reachable commit missing: {commit_id}")
        stack.append((commit_id, True))
        for parent in sorted(commit.parents, reverse=True):
            if parent not in seen:
                stack.append((parent, False))

    return ordered


def build_memory_view(store: Store) -> VerifiedMemoryView:
    """Verify a store, then expose only the history causally reachable from HEAD."""
    report = verify_store(store)
    if not report.ok:
        raise AdapterError("refusing to expose unverified memory: " + report.summary())

    head = store.read_head()
    if not head:
        raise AdapterError("HEAD missing")
    commits = store.load_commits()
    ids = _causal_order(head, commits)

    entries: list[MemoryEntry] = []
    for commit_id in ids:
        commit = commits[commit_id]
        if commit.content == {"type": "genesis"}:
            continue
        entries.append(
            MemoryEntry(
                commit_id=commit.commit_id,
                agent_id=commit.agent_id,
                key_id=commit.key_id,
                memory_type=commit.memory_type,
                session_id=commit.session_id,
                content=commit.content,
                provenance=commit.provenance,
                timestamp=commit.timestamp,
            )
        )
    return VerifiedMemoryView(head=head, entries=tuple(entries))


def context_from_aleth(path: str, passphrase: str) -> dict[str, Any]:
    """Drop-file primitive: unlock .aleth, verify it, return neutral context.

    Plaintext is materialized only inside a temporary directory that is removed
    before this function returns. Callers never need to manage Store layout.
    """
    import tempfile
    from pathlib import Path
    from .container import open_container

    with tempfile.TemporaryDirectory(prefix="alethech-drop-") as tmp:
        store = open_container(path, Path(tmp) / "store", passphrase)
        return build_memory_view(store).to_dict()


def create_chat_envelope(view: VerifiedMemoryView) -> dict[str, Any]:
    """Create provider-neutral chat envelope bound to the verified source HEAD."""
    context = {
        "format": "alethech-context",
        "version": 1,
        "source_head": view.head,
        "items": [
            {
                "id": entry.commit_id,
                "memory_type": entry.memory_type,
                "timestamp": entry.timestamp,
                "content": entry.content,
                "provenance": entry.provenance,
            }
            for entry in view.entries
        ],
    }
    return {
        "format": "alethech-chat-envelope",
        "version": 1,
        "source_head": view.head,
        "context": context,
    }


def validate_writeback_proposal(value: Any) -> dict[str, Any]:
    """Validate the provider-neutral unsigned writeback proposal schema."""
    if not isinstance(value, dict):
        raise AdapterError("invalid writeback proposal")
    if value.get("format") != "alethech-writeback-proposal" or value.get("version") != 1:
        raise AdapterError("unsupported writeback proposal")
    source_head = value.get("source_head")
    if not isinstance(source_head, str) or not source_head.startswith("sha256:"):
        raise AdapterError("invalid writeback source_head")
    items = value.get("items")
    if not isinstance(items, list) or not items or len(items) > 100:
        raise AdapterError("invalid writeback items")
    normalized: list[dict[str, Any]] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("content"), dict):
            raise AdapterError(f"invalid writeback item {i}")
        memory_type = item.get("memory_type")
        if memory_type not in {"semantic", "episodic", "procedural"}:
            raise AdapterError(f"invalid writeback memory_type at {i}")
        source = item.get("source", "provider_proposal")
        if not isinstance(source, str) or not source:
            raise AdapterError(f"invalid writeback source at {i}")
        confidence = item.get("confidence", 1.0)
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
            raise AdapterError(f"invalid writeback confidence at {i}")
        normalized.append({
            "memory_type": memory_type,
            "content": item["content"],
            "source": source,
            "confidence": float(confidence),
        })
    return {
        "format": "alethech-writeback-proposal",
        "version": 1,
        "source_head": source_head,
        "items": normalized,
    }


def accept_writeback_proposal(store: Store, proposal: Any) -> list[str]:
    """Accept an explicitly approved provider proposal through local signing only.

    The proposal is unsigned/untrusted. This function binds it to the current
    verified HEAD, appends a linear sequence of locally signed commits, and
    verifies the complete resulting store before returning commit IDs.
    """
    from .api import Alethech

    normalized = validate_writeback_proposal(proposal)
    before = build_memory_view(store)
    if normalized["source_head"] != before.head:
        raise AdapterError("stale writeback proposal: source_head no longer current")

    agent = Alethech(store)
    created: list[str] = []
    expected_parent = before.head
    for item in normalized["items"]:
        commit = agent.commit(
            item["content"],
            memory_type=item["memory_type"],
            source=item["source"],
            confidence=item["confidence"],
        )
        if commit.parents != [expected_parent]:
            raise AdapterError("writeback commit chain is not linear from source_head")
        created.append(commit.commit_id)
        expected_parent = commit.commit_id

    after = build_memory_view(store)
    if not created or after.head != created[-1]:
        raise AdapterError("writeback did not advance verified HEAD")
    return created
