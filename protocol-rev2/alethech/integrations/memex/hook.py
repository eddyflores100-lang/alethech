"""alethech integrations — memex write-hook.

When memex writes a memory to its ChromaDB store, this hook ALSO creates
a signed MemoryCommit in the alethech store. That makes each memory
cryptographically verifiable without modifying memex's source code.

Usage:
    from alethech.integrations.memex import MemexAlethechHook

    # Wrap an existing DirectStore
    hook = MemexAlethechHook(
        memex_store=existing_direct_store,
        alethech_store_path="/path/to/.alethech",
    )

    # add() now writes to BOTH ChromaDB and alethech
    hook.add("memory text", user_id="agent")

The hook:
1. Calls memex_store.add() (writes to ChromaDB as usual)
2. Creates a MemoryCommit in alethech with:
   - content = {"text": text, "user_id": user_id, "memex_id": returned_id}
   - provenance.source = "memex_write"
   - signed by the alethech identity's active key
3. Returns the same dict that memex_store.add() would return

If alethech is not initialized (no .alethech/ store), the hook silently
skips the commit and only writes to memex. That way the integration is
opt-in: if you don't set up alethech, memex works exactly as before.
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from alethech import crypto
from alethech.objects import MemoryCommit, IdentityRecordV2
from alethech.store import Store, StoreError

logger = logging.getLogger("alethech.integrations.memex")


class MemexAlethechHook:
    """Wrapper around a memex DirectStore that adds alethech signing.

    Drop-in replacement for memex.DirectStore — same interface, but .add()
    also creates a signed MemoryCommit in the alethech store.

    If the alethech store is not initialized (no .alethech/), the hook
    silently skips signing and behaves exactly like the original DirectStore.
    """

    def __init__(self, memex_store: Any, alethech_store_path: str | Path):
        self.memex = memex_store
        self.alethech_path = Path(alethech_store_path)

        # Try to open the alethech store. If it fails, we run in "passthrough" mode.
        self._alethech: Store | None = None
        self._signing_keypair: crypto.KeyPair | None = None
        self._identity: IdentityRecordV2 | None = None

        try:
            store = Store.open(self.alethech_path)
            # Try v0.2 identity first
            v2_identities = store.load_identity_records_v2()
            if v2_identities:
                self._identity = next(iter(v2_identities.values()))
                self._signing_keypair = store.load_signing_key()
                self._alethech = store
                logger.info("alethech hook active (v0.2 identity: %s)", self._identity.agent_id[:30])
                return

            # Try v0.1 (legacy)
            legacy = store.load_identities()
            if legacy:
                self._signing_keypair = store.load_signing_key()
                self._alethech = store
                # Wrap legacy identity in a shim
                ident = next(iter(legacy.values()))
                self._identity = ident
                logger.info("alethech hook active (v0.1 legacy identity: %s)", ident.agent_id[:30])
                return

            logger.warning("alethech store exists but has no identity — running in passthrough mode")
        except (StoreError, Exception) as e:
            logger.info("alethech not initialized (%s) — running in passthrough mode", e)

    @property
    def active(self) -> bool:
        """True if the hook is signing commits."""
        return self._alethech is not None and self._signing_keypair is not None and self._identity is not None

    def add(self, text: str, user_id: str = "agent", metadata: dict | None = None) -> dict[str, Any]:
        """Write a memory to memex AND (if active) create a signed alethech commit.

        Returns the same dict that memex_store.add() returns.
        """
        # Step 1: write to memex as usual
        result = self.memex.add(text, user_id=user_id, metadata=metadata)

        # Step 2: if alethech is active, create a signed MemoryCommit
        if self.active:
            self._sign_memex_write(
                text=text,
                user_id=user_id,
                memex_id=result.get("id", ""),
                metadata=metadata or {},
            )

        return result

    def _sign_memex_write(
        self,
        text: str,
        user_id: str,
        memex_id: str,
        metadata: dict,
    ) -> None:
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

        # Get current HEAD
        head = self._alethech.read_head()
        parents = [head] if head else []

        # Build the commit
        commit = MemoryCommit(
            agent_id=self._identity.agent_id,
            key_id=key_id,
            parents=parents,
            session_id=str(uuid.uuid4()),
            memory_type="semantic",
            content={
                "text": text,
                "user_id": user_id,
                "memex_id": memex_id,
                "source": "memex.write",
            },
            provenance={
                "source": "tool_execution",
                "source_id": memex_id,
                "evidence_refs": [],
                "confidence": 1.0,
            },
        )

        # Sign it
        commit.sign(self._signing_keypair)

        # Write to alethech store
        self._alethech.write_commit(commit)
        self._alethech.write_head(commit.commit_id)

        logger.debug("signed memex write: memex_id=%s → alethech_commit=%s", memex_id, commit.commit_id[:16])

    def search(self, query: str, user_id: str = "agent", limit: int = 5, filters: dict | None = None):
        """Pass-through to memex search."""
        return self.memex.search(query, user_id=user_id, limit=limit, filters=filters)

    def get_all(self, user_id: str = "agent", limit: int = 100000):
        """Pass-through to memex get_all."""
        return self.memex.get_all(user_id=user_id, limit=limit)

    # Pass through any other attribute access to the underlying memex store
    def __getattr__(self, name: str):
        return getattr(self.memex, name)


def verify_memex_integrity(alethech_store_path: str | Path) -> dict:
    """Verify that all memex writes recorded in alethech have valid commits.

    Returns a report:
    {
        "total_commits": N,
        "memex_commits": N,  # commits with content.source == "memex.write"
        "valid_signatures": N,
        "invalid_signatures": N,
        "missing_identity": N,
    }
    """
    store = Store.open(Path(alethech_store_path))
    commits = store.load_commits()
    identities_v2 = store.load_identity_records_v2()
    legacy_identities = store.load_identities()

    # Build a lookup of agent_id → public_key
    key_lookup: dict[tuple[str, str], dict] = {}  # (agent_id, key_id) → public_jwk
    for ident in identities_v2.values():
        for k in ident.active_keys + ident.revoked_keys:
            key_lookup[(ident.agent_id, k["key_id"])] = k["public_key"]
    for ident in legacy_identities.values():
        key_lookup[(ident.agent_id, ident.key_id)] = ident.public_key

    memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]
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
