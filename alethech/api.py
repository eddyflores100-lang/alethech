"""Public Python API for embedding alethech.

This module is intentionally independent of Click. Applications should use
Alethech for programmatic integration and reserve the CLI for humans.
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from cryptography.hazmat.primitives import serialization
from . import crypto
from .objects import Identity, MemoryCommit
from .store import Store, StoreError
from .verify import VerifyReport, verify_store
from .container import seal_store, open_container
from .adapters import VerifiedMemoryView, build_memory_view, context_from_aleth

class AlethechError(Exception):
    """Programmatic API error with stable, user-facing semantics."""

@dataclass
class Alethech:
    """Programmatic handle to one alethech store."""
    store: Store

    @property
    def path(self) -> Path:
        return self.store.root

    @classmethod
    def initialize(cls, path: str | Path) -> "Alethech":
        """Create a new V1 store and its signed genesis commit."""
        path = Path(path)
        signing = crypto.KeyPair.generate()
        recovery = crypto.KeyPair.generate()
        public_jwk = signing.public_jwk()
        agent_id = crypto.derive_agent_id(public_jwk)
        recovery_raw = recovery.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        identity = Identity(agent_id=agent_id, public_key=public_jwk, key_id="key-001",
            recovery_root="ed25519:" + crypto.b64url(recovery_raw))
        try:
            store = Store.init(path)
        except StoreError as exc:
            raise AlethechError(str(exc)) from exc
        store.write_identity(identity)
        store.write_signing_key(signing)
        store.write_recovery_key(recovery)
        store.write_root_key(signing)
        genesis = MemoryCommit(
            agent_id=agent_id, key_id=identity.key_id, parents=[],
            session_id=str(uuid.uuid4()), memory_type="semantic",
            content={"type": "genesis"},
            provenance={"source": "agent_observation", "source_id": None,
                        "evidence_refs": [], "confidence": 1.0},
        )
        genesis.sign(signing)
        store.write_commit(genesis)
        store.write_head(genesis.commit_id)
        return cls(store)

    @classmethod
    def open(cls, path: str | Path) -> "Alethech":
        """Open an existing store without mutating it."""
        try:
            return cls(Store.open(Path(path)))
        except StoreError as exc:
            raise AlethechError(str(exc)) from exc

    @property
    def head(self) -> str:
        head = self.store.read_head()
        if head is None:
            raise AlethechError("HEAD missing")
        return head

    def commit(self, content: dict, *, memory_type: str = "semantic",
               evidence_refs: Iterable[str] = (), session_id: str | None = None) -> MemoryCommit:
        """Create, sign, persist and advance HEAD to a MemoryCommit."""
        if not isinstance(content, dict):
            raise AlethechError("content must be a dict")
        if memory_type not in {"semantic", "episodic", "procedural"}:
            raise AlethechError(f"unsupported memory_type: {memory_type}")
        try:
            signing = self.store.load_signing_key()
            commits = self.store.load_commits()
            evidence = self.store.load_evidence()
            v2 = self.store.load_identity_records_v2()
            legacy = self.store.load_identities()
        except StoreError as exc:
            raise AlethechError(str(exc)) from exc
        head = self.head
        if head not in commits:
            raise AlethechError(f"HEAD points to nonexistent commit {head}")
        refs = list(evidence_refs)
        missing = [eid for eid in refs if eid not in evidence]
        if missing:
            raise AlethechError(f"evidence_id not found: {missing[0]}")
        if v2:
            identity = next(iter(v2.values()))
            if not identity.active_keys:
                raise AlethechError("no active key in v0.2 identity")
            agent_id = identity.agent_id
            key_id = identity.active_keys[0]["key_id"]
        elif legacy:
            identity = next(iter(legacy.values()))
            if not identity.verify_self():
                raise AlethechError("identity_mismatch")
            agent_id = identity.agent_id
            key_id = identity.key_id
        else:
            raise AlethechError("no identity in store")
        commit = MemoryCommit(
            agent_id=agent_id, key_id=key_id, parents=[head],
            session_id=session_id or str(uuid.uuid4()), memory_type=memory_type,
            content=content,
            provenance={"source": "agent_observation", "source_id": str(uuid.uuid4()),
                        "evidence_refs": refs, "confidence": 1.0},
        )
        commit.sign(signing)
        self.store.write_commit(commit)
        self.store.write_head(commit.commit_id)
        return commit

    def verify(self) -> VerifyReport:
        """Run the standalone verifier against this store."""
        return verify_store(self.store)

    def memory_view(self) -> VerifiedMemoryView:
        """Return a verified, backend-neutral causal memory view for adapters."""
        return build_memory_view(self.store)

    def context(self) -> dict:
        """Return the verified neutral adapter payload as a plain dictionary."""
        return self.memory_view().to_dict()

    def seal(self, output: str | Path, passphrase: str) -> Path:
        """Export this memory as one encrypted portable .aleth file."""
        return seal_store(self.store, output, passphrase)

    @classmethod
    def open_aleth(cls, path: str | Path, destination: str | Path, passphrase: str) -> "Alethech":
        """Open an encrypted .aleth into a new local working store."""
        return cls(open_container(path, destination, passphrase))

    @staticmethod
    def drop_context(path: str | Path, passphrase: str) -> dict:
        """Unlock a dropped .aleth, verify it, and return neutral context only."""
        return context_from_aleth(str(path), passphrase)
