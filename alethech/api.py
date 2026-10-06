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
from .objects import Identity, MemoryCommit, EvidenceCommit
from .store import Store, StoreError
from .verify import VerifyReport, verify_store
from .container import MAGIC, seal_store, open_container, rekey_container
from .container_v2 import (
    MAGIC_V2,
    migrate_v1_to_v2,
    open_container_v2,
    recover_container_v2,
    seal_store_v2,
    rekey_container_v2,
)
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
               evidence_refs: Iterable[str] = (), session_id: str | None = None,
               source: str = "agent_observation", confidence: float = 1.0) -> MemoryCommit:
        """Create, sign, persist and advance HEAD to a MemoryCommit."""
        if not isinstance(content, dict):
            raise AlethechError("content must be a dict")
        if memory_type not in {"semantic", "episodic", "procedural"}:
            raise AlethechError(f"unsupported memory_type: {memory_type}")
        if not isinstance(source, str) or not source:
            raise AlethechError("source must be a non-empty string")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= float(confidence) <= 1:
            raise AlethechError("confidence must be between 0 and 1")
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
            # FIX local (Task 106, 2026-10-06): pick the identity whose public key
            # matches the store signing key; next(iter(...)) is arbitrary when
            # several identities are registered (post-rotation) and yields
            # signature_invalid commits.
            _sign_x = None
            try:
                _sign_x = signing.public_jwk().get("x")
            except Exception:
                pass
            identity = None
            if _sign_x:
                for _cand in legacy.values():
                    _pk = getattr(_cand, "public_key", None)
                    _x = _pk.get("x") if isinstance(_pk, dict) else None
                    if _x == _sign_x and _cand.verify_self():
                        identity = _cand
                        break
            if identity is None:
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
            provenance={"source": source, "source_id": str(uuid.uuid4()),
                        "evidence_refs": refs, "confidence": float(confidence)},
        )
        commit.sign(signing)
        self.store.write_commit(commit)
        self.store.write_head(commit.commit_id)
        return commit

    def evidence(
        self,
        *,
        tool: str,
        input_bytes: bytes,
        output_bytes: bytes,
        result: str = "success",
        tool_version: str = "",
        artifacts: dict[str, bytes] | None = None,
    ) -> EvidenceCommit:
        """Create signed evidence without going through Click or filesystem inputs."""
        if result not in {"success", "failure", "timeout"}:
            raise AlethechError(f"unsupported evidence result: {result}")
        if not isinstance(input_bytes, (bytes, bytearray)) or not isinstance(output_bytes, (bytes, bytearray)):
            raise AlethechError("input_bytes and output_bytes must be bytes")

        try:
            signing = self.store.load_signing_key()
            v2 = self.store.load_identity_records_v2()
            legacy = self.store.load_identities()
        except StoreError as exc:
            raise AlethechError(str(exc)) from exc

        if v2:
            identity = next(iter(v2.values()))
            signing_jwk = signing.public_jwk()
            matches = [
                item for item in identity.active_keys
                if isinstance(item, dict) and item.get("public_key") == signing_jwk
            ]
            if not matches:
                raise AlethechError("signing key does not match an active identity key")
            agent_id = identity.agent_id
            key_id = matches[0]["key_id"]
        elif legacy:
            identity = next(iter(legacy.values()))
            if identity.public_key != signing.public_jwk():
                raise AlethechError("signing key does not match identity")
            agent_id = identity.agent_id
            key_id = identity.key_id
        else:
            raise AlethechError("no identity in store")

        artifact_meta = []
        for name, data in (artifacts or {}).items():
            if not isinstance(name, str) or not name:
                raise AlethechError("artifact name must be a non-empty string")
            if not isinstance(data, (bytes, bytearray)):
                raise AlethechError("artifact content must be bytes")
            if len(data) > 100 * 1024 * 1024:
                raise AlethechError(f"artifact too large: {name}")
            h = self.store.write_artifact(bytes(data))
            artifact_meta.append({"name": name, "hash": h, "size": len(data)})

        ev = EvidenceCommit(
            agent_id=agent_id,
            key_id=key_id,
            event_type="tool_execution",
            tool=tool,
            tool_version=tool_version,
            input_hash="sha256:" + crypto.sha256_hex(bytes(input_bytes)),
            output_hash="sha256:" + crypto.sha256_hex(bytes(output_bytes)),
            artifacts=artifact_meta,
            result=result,
        )
        ev.sign(signing)
        self.store.write_evidence(ev)
        return ev

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
        """Open ALETH001 or ALETH002 with a passphrase into a local working store."""
        path = Path(path)
        with path.open("rb") as handle:
            magic = handle.read(8)
        if magic == MAGIC:
            return cls(open_container(path, destination, passphrase))
        if magic == MAGIC_V2:
            return cls(open_container_v2(path, destination, passphrase=passphrase))
        raise AlethechError("unsupported .aleth container magic")

    def seal_v2(
        self,
        output: str | Path,
        passphrase: str,
        *,
        create_recovery: bool = True,
    ) -> tuple[Path, str | None]:
        """Export this memory as ALETH002 with optional recovery code."""
        return seal_store_v2(
            self.store,
            output,
            passphrase,
            create_recovery=create_recovery,
        )

    @classmethod
    def open_aleth_v2(
        cls,
        path: str | Path,
        destination: str | Path,
        *,
        passphrase: str | None = None,
        recovery_code: str | None = None,
    ) -> "Alethech":
        """Open ALETH002 using exactly one passphrase or recovery code."""
        return cls(
            open_container_v2(
                path,
                destination,
                passphrase=passphrase,
                recovery_code=recovery_code,
            )
        )

    @staticmethod
    def recover_aleth_v2(
        path: str | Path,
        output: str | Path,
        recovery_code: str,
        new_passphrase: str,
        *,
        rotate_recovery: bool = False,
    ) -> tuple[Path, str]:
        """Replace a forgotten ALETH002 passphrase using its recovery code."""
        return recover_container_v2(
            path,
            output,
            recovery_code,
            new_passphrase,
            rotate_recovery=rotate_recovery,
        )

    @staticmethod
    def migrate_aleth_v1_to_v2(
        path: str | Path,
        output: str | Path,
        old_passphrase: str,
        new_passphrase: str,
        *,
        create_recovery: bool = True,
        replace_source: bool = False,
    ) -> tuple[Path, str | None]:
        """Explicitly migrate ALETH001 to ALETH002 after full verification."""
        return migrate_v1_to_v2(
            path,
            output,
            old_passphrase,
            new_passphrase,
            create_recovery=create_recovery,
            replace_source=replace_source,
        )

    @staticmethod
    def drop_context(path: str | Path, passphrase: str) -> dict:
        """Unlock a dropped .aleth, verify it, and return neutral context only."""
        return context_from_aleth(str(path), passphrase)


    @staticmethod
    def rekey_aleth(
        path: str | Path,
        output: str | Path,
        old_passphrase: str,
        new_passphrase: str,
        *,
        recovery_code: str | None = None,
    ) -> Path:
        """Rotate encryption, preserving v2 recovery with its explicit credential."""
        with Path(path).open("rb") as handle:
            magic = handle.read(8)
        if magic == MAGIC:
            if recovery_code is not None:
                raise AlethechError("ALETH001 has no recovery slot")
            return rekey_container(path, output, old_passphrase, new_passphrase)
        if magic == MAGIC_V2:
            return rekey_container_v2(path, output, old_passphrase, new_passphrase,
                                      recovery_code=recovery_code)
        raise AlethechError("unsupported .aleth container magic")
