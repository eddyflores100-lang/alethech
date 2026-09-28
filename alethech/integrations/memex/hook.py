"""alethech integrations — memex write-hook (rev 0.4.0).

When memex writes a memory to its ChromaDB store, this hook ALSO creates
a signed MemoryCommit in the alethech store. That makes each memory
cryptographically verifiable without modifying memex's source code.

rev 0.4.0 adds:
- Atomicity with compensating delete (A1, R1)
- Idempotency with stable key (E1, E2)
- Wallet multiple with explicit identity (H1)
- Intra-process locking (C1)
- INCOMPLETE_COMPENSATION persistent and recoverable

Contract: docs/contrato-hook-0-4-0.md (rev 2 APPROVED)
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alethech import crypto
from alethech.objects import MemoryCommit, IdentityRecordV2
from alethech.store import Store, StoreError

logger = logging.getLogger("alethech.integrations.memex")


def utc_now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


class CompensatedWriteResult(dict):
    """Result of hook.add(). Dict-like for backwards compat, with extra fields.

    Fields:
        id: memex_id (str | None) — the ChromaDB memory ID
        text: the original text
        success: whether the operation completed successfully
        alethech_commit_id: the commit ID (str | None)
        compensation_status: "not_needed" | "succeeded" | "incomplete"
        error: error message (str | None)
    """

    def __init__(
        self,
        success: bool,
        memex_id: str | None = None,
        text: str = "",
        alethech_commit_id: str | None = None,
        compensation_status: str = "not_needed",
        error: str | None = None,
    ):
        super().__init__()
        self["id"] = memex_id
        self["text"] = text
        self["success"] = success
        self["alethech_commit_id"] = alethech_commit_id
        self["compensation_status"] = compensation_status
        self["error"] = error

    @property
    def success(self) -> bool:
        return self["success"]

    @property
    def compensation_status(self) -> str:
        return self["compensation_status"]


class MemexAlethechHook:
    """Wrapper around a memex DirectStore that adds alethech signing.

    rev 0.4.0: atomicity, idempotency, wallet multiple, intra-process lock.

    Contract: docs/contrato-hook-0-4-0.md (rev 2 APPROVED)
    """

    def __init__(
        self,
        memex_store: Any,
        alethech_store_path: str | Path,
        identity: str | None = None,
    ):
        self.memex = memex_store
        self.alethech_path = Path(alethech_store_path)
        self._lock = threading.Lock()
        self._identity_param = identity

        self._alethech: Store | None = None
        self._signing_keypair: crypto.KeyPair | None = None
        self._identity: Any = None  # IdentityRecordV2 or legacy Identity

        try:
            store = Store.open(self.alethech_path)

            # Try v0.2 identities first
            v2_identities = store.load_identity_records_v2()
            if v2_identities:
                # If identity param given, select it; else use first
                if self._identity_param:
                    found = None
                    for agent_id, ident in v2_identities.items():
                        if agent_id == self._identity_param:
                            found = ident
                            break
                    if found is None:
                        raise ValueError(
                            f"identity not in store: {self._identity_param}"
                        )
                    self._identity = found
                else:
                    self._identity = next(iter(v2_identities.values()))

                self._signing_keypair = store.load_signing_key()
                self._alethech = store
                logger.info(
                    "alethech hook active (v0.2 identity: %s)",
                    self._identity.agent_id[:30],
                )
                return

            # Try v0.1 (legacy)
            legacy = store.load_identities()
            if legacy:
                if self._identity_param:
                    found = None
                    for agent_id, ident in legacy.items():
                        if agent_id == self._identity_param:
                            found = ident
                            break
                    if found is None:
                        raise ValueError(
                            f"identity not in store: {self._identity_param}"
                        )
                    self._identity = found
                else:
                    self._identity = next(iter(legacy.values()))

                self._signing_keypair = store.load_signing_key()
                self._alethech = store
                logger.info(
                    "alethech hook active (v0.1 legacy: %s)",
                    self._identity.agent_id[:30],
                )
                return

            logger.warning(
                "alethech store exists but has no identity — passthrough mode"
            )
        except ValueError:
            raise  # identity not in store — propagate
        except (StoreError, Exception) as e:
            logger.info(
                "alethech not initialized (%s) — passthrough mode", e
            )

    @property
    def active(self) -> bool:
        return (
            self._alethech is not None
            and self._signing_keypair is not None
            and self._identity is not None
        )

    def add(
        self,
        text: str,
        user_id: str = "agent",
        metadata: dict | None = None,
        idempotency_key: str | None = None,
    ) -> CompensatedWriteResult:
        """Write a memory to memex AND (if active) create a signed alethech commit.

        Returns CompensatedWriteResult (dict-like for backwards compat).
        """
        with self._lock:
            # 1. Idempotency check — if key given, look up before writing
            if idempotency_key and self.active:
                existing = self._find_by_idempotency_key(idempotency_key)
                if existing is not None:
                    # BUG 4 FIX: check that text matches
                    existing_text = existing.content.get("text", "")
                    if existing_text != text:
                        logger.warning(
                            "idempotency conflict: key=%s existing_text=%r new_text=%r",
                            idempotency_key, existing_text[:50], text[:50]
                        )
                        return CompensatedWriteResult(
                            success=False,
                            memex_id=existing.content.get("memex_id"),
                            text=text,
                            alethech_commit_id=existing.commit_id,
                            compensation_status="not_needed",
                            error=f"idempotency_conflict: key={idempotency_key} already used with different text",
                        )
                    logger.info(
                        "idempotent hit: key=%s → existing commit %s",
                        idempotency_key,
                        existing.commit_id[:16],
                    )
                    return CompensatedWriteResult(
                        success=True,
                        memex_id=existing.content.get("memex_id"),
                        text=text,
                        alethech_commit_id=existing.commit_id,
                        compensation_status="not_needed",
                    )

            # 2. ChromaDB write (may raise)
            try:
                result = self.memex.add(text, user_id=user_id, metadata=metadata)
            except Exception as e:
                return CompensatedWriteResult(
                    success=False,
                    memex_id=None,
                    text=text,
                    compensation_status="not_needed",
                    error=f"chromadb_write_failed: {e}",
                )

            memex_id = result.get("id", "")

            # 3. Alethech commit (if active)
            if self.active:
                try:
                    commit = self._sign_memex_write(
                        text, user_id, memex_id, metadata or {}, idempotency_key
                    )
                    return CompensatedWriteResult(
                        success=True,
                        memex_id=memex_id,
                        text=text,
                        alethech_commit_id=commit.commit_id,
                        compensation_status="not_needed",
                    )
                except Exception as e:
                    # 4. Compensating delete
                    comp_status = self._compensate(memex_id)

                    if comp_status == "incomplete":
                        # Persist INCOMPLETE_COMPENSATION
                        key_for_record = idempotency_key or str(uuid.uuid4())
                        self._persist_incomplete_compensation(
                            key_for_record,
                            memex_id,
                            text,
                            user_id,
                            metadata or {},
                            str(e),
                        )

                    return CompensatedWriteResult(
                        success=False,
                        memex_id=memex_id if comp_status == "incomplete" else None,
                        text=text,
                        alethech_commit_id=None,
                        compensation_status=comp_status,
                        error=f"alethech_commit_failed: {e}",
                    )

            # Passthrough mode (alethech not active)
            return CompensatedWriteResult(
                success=True,
                memex_id=memex_id,
                text=text,
                alethech_commit_id=None,
                compensation_status="not_needed",
            )

    def _compensate(self, memex_id: str) -> str:
        """Try to delete the memory from ChromaDB. Returns 'succeeded' or 'incomplete'."""
        try:
            self.memex.delete(memex_id)
            return "succeeded"
        except Exception as e:
            logger.error(
                "compensating delete failed for memex_id=%s: %s", memex_id, e
            )
            return "incomplete"

    def _persist_incomplete_compensation(
        self,
        idempotency_key: str,
        memex_id: str,
        text: str,
        user_id: str,
        metadata: dict,
        error: str,
    ) -> None:
        """Persist INCOMPLETE_COMPENSATION to disk for recovery post-restart."""
        if not self._alethech:
            return
        comp_dir = self._alethech.root / "incomplete_compensations"
        comp_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "idempotency_key": idempotency_key,
            "memex_id": memex_id,
            "text": text,
            "user_id": user_id,
            "metadata": metadata,
            "alethech_commit_id": None,
            "created_at": utc_now_iso(),
            "status": "incomplete",
            "compensation_attempted": True,
            "compensation_succeeded": False,
            "compensation_error": error,
        }

        path = comp_dir / f"{idempotency_key}.json"
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        logger.warning(
            "INCOMPLETE_COMPENSATION persisted: key=%s, memex_id=%s",
            idempotency_key,
            memex_id,
        )

    def discover_incomplete_compensations(self) -> list[dict]:
        """Read all incomplete_compensations/*.json files.

        Returns list of pending operations. Call this at startup
        to discover operations that need manual resolution.
        """
        if not self._alethech:
            return []
        comp_dir = self._alethech.root / "incomplete_compensations"
        if not comp_dir.is_dir():
            return []
        results = []
        for path in comp_dir.glob("*.json"):
            try:
                results.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception as e:
                logger.error("failed to read %s: %s", path, e)
        return results

    def _find_by_idempotency_key(self, key: str) -> MemoryCommit | None:
        """Find a successful commit with the given idempotency_key.

        A commit is 'successful' for idempotency when:
        1. The commit exists and its signature verifies
        2. The corresponding ChromaDB memory exists and is retrievable
        3. The idempotency_key is in commit.content.idempotency_key
        """
        if not self._alethech:
            return None

        for c in self._alethech.load_commits().values():
            if c.content.get("idempotency_key") != key:
                continue
            if c.content.get("source") != "memex.write":
                continue

            # 1. Verify commit signature
            pub_jwk = self._get_public_jwk_for_key(c.key_id)
            if pub_jwk is None:
                continue  # can't verify — skip
            if not c.verify(pub_jwk):
                continue  # signature invalid — skip

            # 2. Verify ChromaDB memory exists
            memex_id = c.content.get("memex_id")
            if not memex_id:
                continue
            if not self._verify_memex_memory_exists(memex_id, c.content.get("user_id", "agent")):
                continue  # memory gone — operation not successful

            return c

        return None

    def _get_public_jwk_for_key(self, key_id: str) -> dict | None:
        """Get the public key JWK for a given key_id from the current identity."""
        if self._identity is None:
            return None

        # v0.2 identity
        if hasattr(self._identity, "active_keys"):
            for k in self._identity.active_keys + self._identity.revoked_keys:
                if k.get("key_id") == key_id:
                    return k.get("public_key")
            return None

        # v0.1 legacy
        if hasattr(self._identity, "public_key") and hasattr(self._identity, "key_id"):
            if self._identity.key_id == key_id:
                return self._identity.public_key
        return None

    def _verify_memex_memory_exists(self, memex_id: str, user_id: str) -> bool:
        """Check if a memory exists in ChromaDB by ID."""
        try:
            all_memories = self.memex.get_all(user_id=user_id, limit=100000)
            if isinstance(all_memories, dict):
                results = all_memories.get("results", all_memories.get("memories", []))
            elif isinstance(all_memories, list):
                results = all_memories
            else:
                results = []

            for m in results:
                if isinstance(m, dict) and m.get("id") == memex_id:
                    return True
            return False
        except Exception:
            return False

    def _sign_memex_write(
        self,
        text: str,
        user_id: str,
        memex_id: str,
        metadata: dict,
        idempotency_key: str | None = None,
    ) -> MemoryCommit:
        """Create a MemoryCommit referencing this memex write."""
        assert self._alethech is not None
        assert self._signing_keypair is not None
        assert self._identity is not None

        # Determine key_id
        if hasattr(self._identity, "active_keys") and self._identity.active_keys:
            key_id = self._identity.active_keys[0]["key_id"]
        elif hasattr(self._identity, "key_id"):
            key_id = self._identity.key_id
        else:
            key_id = "key-001"

        head = self._alethech.read_head()
        parents = [head] if head else []

        content = {
            "text": text,
            "user_id": user_id,
            "memex_id": memex_id,
            "source": "memex.write",
        }
        if idempotency_key:
            content["idempotency_key"] = idempotency_key

        commit = MemoryCommit(
            agent_id=self._identity.agent_id,
            key_id=key_id,
            parents=parents,
            session_id=str(uuid.uuid4()),
            memory_type="semantic",
            content=content,
            provenance={
                "source": "tool_execution",
                "source_id": memex_id,
                "evidence_refs": [],
                "confidence": 1.0,
            },
        )

        commit.sign(self._signing_keypair)
        self._alethech.write_commit(commit)
        self._alethech.write_head(commit.commit_id)

        logger.debug(
            "signed memex write: memex_id=%s → commit=%s",
            memex_id,
            commit.commit_id[:16],
        )
        return commit

    def search(self, query, user_id="agent", limit=5, filters=None):
        return self.memex.search(query, user_id=user_id, limit=limit, filters=filters)

    def get_all(self, user_id="agent", limit=100000):
        return self.memex.get_all(user_id=user_id, limit=limit)

    def __getattr__(self, name):
        return getattr(self.memex, name)


def verify_memex_integrity(alethech_store_path: str | Path) -> dict:
    """Verify that all memex writes recorded in alethech have valid commits."""
    store = Store.open(Path(alethech_store_path))
    commits = store.load_commits()
    identities_v2 = store.load_identity_records_v2()
    legacy_identities = store.load_identities()

    key_lookup = {}
    for ident in identities_v2.values():
        for k in ident.active_keys + ident.revoked_keys:
            key_lookup[(ident.agent_id, k["key_id"])] = k["public_key"]
    for ident in legacy_identities.values():
        key_lookup[(ident.agent_id, ident.key_id)] = ident.public_key

    memex_commits = [
        c for c in commits.values() if c.content.get("source") == "memex.write"
    ]
    valid = 0
    invalid = 0
    missing_identity = 0

    for commit in memex_commits:
        pub_jwk = key_lookup.get((commit.agent_id, commit.key_id))
        if pub_jwk is None:
            missing_identity += 1
            continue
        if commit.verify(pub_jwk):
            valid += 1
        else:
            invalid += 1

    return {
        "total_commits": len(commits),
        "memex_commits": len(memex_commits),
        "valid_signatures": valid,
        "invalid_signatures": invalid,
        "missing_identity": missing_identity,
    }
