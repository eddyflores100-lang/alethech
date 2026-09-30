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
