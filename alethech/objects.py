"""Verifiable objects: Identity, MemoryCommit, EvidenceCommit, Checkpoint.

Each object knows how to:
- canonicalize itself (excluding commit_id and signature)
- compute its commit_id (= sha256 of canonical bytes without commit_id)
- re-canonicalize with commit_id (excluding signature)
- be signed by a private key
- be verified by a public key
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import crypto
from .canonical import canonical_json, canonical_json_bytes


# ---------- helpers ----------

def utc_now_iso() -> str:
    """ISO 8601 UTC timestamp with milliseconds."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def sha256_commit_id(canonical_bytes: bytes) -> str:
    """commit_id = 'sha256:' + hex(sha256(canonical_bytes))"""
    return "sha256:" + crypto.sha256_hex(canonical_bytes)


# ---------- Identity ----------

@dataclass
class Identity:
    """Agent identity record. Public only — private keys live in .alethech/keys/."""

    agent_id: str  # did:alethech:...
    public_key: dict  # JWK {kty, crv, x}
    key_id: str = "key-001"
    created_at: str = field(default_factory=utc_now_iso)
    recovery_root: str = ""  # base64url of recovery public key, optional

    def to_dict(self) -> dict:
        return {
            "type": "Identity",
            "version": 1,
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "recovery_root": self.recovery_root,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Identity":  # typed
        if d.get("type") != "Identity":
            raise ValueError(f"not an Identity record: type={d.get('type')}")
        return cls(
            agent_id=d["agent_id"],
            public_key=d["public_key"],
            key_id=d.get("key_id", "key-001"),
            created_at=d["created_at"],
            recovery_root=d.get("recovery_root", ""),
        )

    def verify_self(self) -> bool:
        """Verify that agent_id derives from public_key (corrección 1 de GPT)."""
        # BUG 5 FIX: validate JWK structure first
        if not isinstance(self.public_key, dict):
            return False
        if self.public_key.get("kty") != "OKP":
            return False
        if self.public_key.get("crv") != "Ed25519":
            return False
        x = self.public_key.get("x")
        if not isinstance(x, str) or not x:
            return False
        # Try to decode the base64url to verify it's valid
        try:
            crypto.b64url_decode(x)
        except Exception:
            return False
        # Now check derivation
        try:
            derived = crypto.derive_agent_id(self.public_key)
            return derived == self.agent_id
        except Exception:
            return False


# ---------- base signed object ----------

@dataclass
class SignedObject:
    """Base for objects that have a commit_id and a signature.

    Subclasses define the schema. They MUST override:
    - object_type() -> str
    - to_signable_dict() -> dict (the object minus commit_id and signature)
    - to_signed_dict() -> dict (full object including commit_id and signature)
    """

    commit_id: str = ""
    signature: str = ""

    @staticmethod
    def object_type() -> str:
        raise NotImplementedError

    def to_signable_dict(self) -> dict:
        """Return the object WITHOUT commit_id and WITHOUT signature."""
        raise NotImplementedError

    def to_signed_dict(self) -> dict:
        """Return the full object, INCLUDING commit_id and signature."""
        raise NotImplementedError

    # --- commit_id computation ---

    def compute_commit_id(self) -> str:
        """sha256 of canonical bytes (without commit_id and signature)."""
        signable = self.to_signable_dict()
        canonical = canonical_json_bytes(signable)
        return sha256_commit_id(canonical)

    # --- canonical bytes used for signing ---

    def canonical_bytes_for_signing(self) -> bytes:
        """Canonical bytes INCLUDING commit_id, EXCLUDING signature.

        This is what Ed25519 signs.
        """
        # build a dict with commit_id but without signature
        signable = self.to_signable_dict()
        signable["commit_id"] = self.commit_id
        return canonical_json_bytes(signable)

    # --- sign / verify ---

    def sign(self, keypair: crypto.KeyPair) -> None:
        self.commit_id = self.compute_commit_id()
        msg = self.canonical_bytes_for_signing()
        sig = keypair.sign(msg)
        self.signature = "ed25519:" + crypto.b64url(sig)

    def verify(self, public_jwk: dict) -> bool:
        """Verify signature AND that commit_id matches content.

        Steps (6 total, corrección 1):
        1. Reconstruct canonical_bytes_with_commit_id (obj with commit_id, no signature)
        2. Verify Ed25519(public_key, canonical_bytes_with_commit_id, signature)
        3. Reconstruct canonical_bytes (no commit_id, no signature)
        4. Recompute sha256(canonical_bytes)
        5. Compare with declared commit_id
        6. Caller must verify agent_id <-> public_key separately
        """
        if not self.commit_id or not self.signature:
            return False
        if not self.signature.startswith("ed25519:"):
            return False
        sig_b64 = self.signature[len("ed25519:"):]
        try:
            sig_bytes = crypto.b64url_decode(sig_b64)
        except Exception:
            return False

        # 1. canonical with commit_id, no signature
        msg = self.canonical_bytes_for_signing()

        # 2. verify signature
        try:
            pub = crypto.KeyPair.public_from_jwk(public_jwk)
        except Exception:
            return False
        if not crypto.KeyPair.verify(pub, sig_bytes, msg):
            return False

        # 3. canonical without commit_id, no signature
        signable = self.to_signable_dict()
        canonical = canonical_json_bytes(signable)

        # 4. recompute hash
        recomputed = sha256_commit_id(canonical)

        # 5. compare
        return recomputed == self.commit_id


# ---------- MemoryCommit ----------

@dataclass
class MemoryCommit(SignedObject):
    """A signed memory commit, linked to its parents in the DAG."""

    agent_id: str = ""
    key_id: str = "key-001"
    parents: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now_iso)
    session_id: str = ""
    memory_type: str = "semantic"  # semantic|episodic|procedural
    content: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)

    @staticmethod
    def object_type() -> str:
        return "MemoryCommit"

    def to_signable_dict(self) -> dict:
        return {
            "type": "MemoryCommit",
            "version": 1,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "parents": self.parents,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "provenance": self.provenance,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["commit_id"] = self.commit_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryCommit":
        if d.get("type") != "MemoryCommit":
            raise ValueError(f"not a MemoryCommit: type={d.get('type')}")
        return cls(
            agent_id=d.get("agent_id", ""),
            key_id=d.get("key_id", "key-001"),
            parents=d.get("parents", []),
            timestamp=d["timestamp"],
            session_id=d.get("session_id", ""),
            memory_type=d.get("memory_type", "semantic"),
            content=d.get("content", {}),
            provenance=d.get("provenance", {}),
            commit_id=d.get("commit_id", ""),
            signature=d.get("signature", ""),
        )


# ---------- EvidenceCommit ----------

@dataclass
class EvidenceCommit(SignedObject):
    """A signed evidence record. Atomic event, not part of the DAG."""

    agent_id: str = ""
    key_id: str = "key-001"
    timestamp: str = field(default_factory=utc_now_iso)
    event_type: str = "tool_execution"
    tool: str = ""
    tool_version: str = ""
    input_hash: str = ""
    output_hash: str = ""
    artifacts: list[dict] = field(default_factory=list)
    result: str = "success"

    @staticmethod
    def object_type() -> str:
        return "EvidenceCommit"

    def to_signable_dict(self) -> dict:
        return {
            "type": "EvidenceCommit",
            "version": 1,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "artifacts": self.artifacts,
            "result": self.result,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["commit_id"] = self.commit_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceCommit":
        if d.get("type") != "EvidenceCommit":
            raise ValueError(f"not an EvidenceCommit: type={d.get('type')}")
        return cls(
            agent_id=d.get("agent_id", ""),
            key_id=d.get("key_id", "key-001"),
            timestamp=d["timestamp"],
            event_type=d.get("event_type", "tool_execution"),
            tool=d.get("tool", ""),
            tool_version=d.get("tool_version", ""),
            input_hash=d.get("input_hash", ""),
            output_hash=d.get("output_hash", ""),
            artifacts=d.get("artifacts", []),
            result=d.get("result", "success"),
            commit_id=d.get("commit_id", ""),
            signature=d.get("signature", ""),
        )


# ---------- Checkpoint ----------

@dataclass
class Checkpoint(SignedObject):
    """A checkpoint signed by an agent. Preserved externally to detect rollback.

    Without an external checkpoint, `verify` can only prove integrity —
    it cannot prove continuity (i.e. that the presented history is the
    most recent one). With a checkpoint, it can also prove that the
    presented history continues from that checkpoint.

    0.6.0 ANTI-ROLLBACK: the `sequence` field provides monotonic anti-rollback.
    A consumer that has previously seen a checkpoint with sequence=N must
    reject any checkpoint with sequence < N. This is independent of
    timestamps — the system clock is NOT the authority.

    The sequence is set by the agent at checkpoint emission time and must
    be strictly increasing. The verifier does NOT enforce that the
    sequence matches any internal counter (the agent is the authority),
    but a downstream consumer can use it to detect rollback:

        if new_checkpoint.sequence <= last_known_sequence:
            reject("rollback detected: sequence went backwards")

    This closes the gap where a correctly-signed but old checkpoint
    could be presented as current.
    """

    agent_id: str = ""
    head_commit_id: str = ""
    commit_count: int = 0
    evidence_count: int = 0
    sequence: int = 0  # 0.6.0: monotonic anti-rollback counter
    created_at: str = field(default_factory=utc_now_iso)

    @staticmethod
    def object_type() -> str:
        return "Checkpoint"

    def to_signable_dict(self) -> dict:
        return {
            "type": "Checkpoint",
            "version": 1,
            "agent_id": self.agent_id,
            "head_commit_id": self.head_commit_id,
            "commit_count": self.commit_count,
            "evidence_count": self.evidence_count,
            "sequence": self.sequence,
            "created_at": self.created_at,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["checkpoint_id"] = self.commit_id  # field name in protocol is checkpoint_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Checkpoint":
        if d.get("type") != "Checkpoint":
            raise ValueError(f"not a Checkpoint: type={d.get('type')}")
        return cls(
            agent_id=d.get("agent_id", ""),
            head_commit_id=d.get("head_commit_id", ""),
            commit_count=d.get("commit_count", 0),
            evidence_count=d.get("evidence_count", 0),
            sequence=d.get("sequence", 0),  # 0.6.0: backward-compat with old checkpoints
            created_at=d["created_at"],
            commit_id=d.get("checkpoint_id", d.get("commit_id", "")),
            signature=d.get("signature", ""),
        )


# ============================================================================
# rev 3 — Identity layer objects
# ============================================================================


@dataclass
class RootAuthority(SignedObject):
    """The root authority for an identity. Inmutable for a given identity.

    Only used for governance: key grants, key revokes, key rotations, migrations.
    Does NOT sign commits or evidence.
    """

    root_id: str = ""  # did:alethech:root:<base32(sha256(root_public_jwk)[0:16])>
    root_public_key: dict = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    recovery_quorum: dict = field(default_factory=lambda: {"type": "single", "threshold": 1, "members": []})

    @staticmethod
    def object_type() -> str:
        return "RootAuthority"

    def to_signable_dict(self) -> dict:
        return {
            "type": "RootAuthority",
            "version": 1,
            "root_id": self.root_id,
            "root_public_key": self.root_public_key,
            "created_at": self.created_at,
            "recovery_quorum": self.recovery_quorum,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["commit_id"] = self.commit_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RootAuthority":
        if d.get("type") != "RootAuthority":
            raise ValueError(f"not a RootAuthority: type={d.get('type')}")
        return cls(
            root_id=d.get("root_id", ""),
            root_public_key=d.get("root_public_key", {}),
            created_at=d.get("created_at", utc_now_iso()),
            recovery_quorum=d.get("recovery_quorum", {"type": "single", "threshold": 1, "members": []}),
            commit_id=d.get("commit_id", ""),
            signature=d.get("signature", ""),
        )

    def verify_self(self) -> bool:
        """Verify that root_id derives from root_public_key."""
        derived = "did:alethech:root:" + crypto.b32lower(crypto.sha256(
            canonical_json_bytes(self.root_public_key)
        )[0:16])
        return derived == self.root_id


@dataclass
class IdentityRecordV2(SignedObject):
    """Identity record rev 2 — agent_id derives from root, not operational key.

    Contains:
    - agent_id (derived from root_public_key)
    - root_id (link to RootAuthority)
    - active_keys[] (each with KeyAuthorization commit_id)
    - revoked_keys[] (each with cutoff_head from the KeyRotation that revoked it)
    """

    agent_id: str = ""
    root_id: str = ""
    root_public_key: dict = field(default_factory=dict)
    active_keys: list = field(default_factory=list)  # [{key_id, public_key, authorized_by, authorized_at, expires_at}]
    revoked_keys: list = field(default_factory=list)  # [{key_id, public_key, revoked_at, revoked_by, cutoff_head}]
    created_at: str = field(default_factory=utc_now_iso)

    @staticmethod
    def object_type() -> str:
        return "IdentityRecordV2"

    def to_signable_dict(self) -> dict:
        return {
            "type": "IdentityRecordV2",
            "version": 2,
            "agent_id": self.agent_id,
            "root_id": self.root_id,
            "root_public_key": self.root_public_key,
            "active_keys": self.active_keys,
            "revoked_keys": self.revoked_keys,
            "created_at": self.created_at,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["commit_id"] = self.commit_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "IdentityRecordV2":
        if d.get("type") not in ("IdentityRecordV2", "Identity"):
            raise ValueError(f"not an IdentityRecordV2: type={d.get('type')}")
        return cls(
            agent_id=d.get("agent_id", ""),
            root_id=d.get("root_id", ""),
            root_public_key=d.get("root_public_key", d.get("public_key", {})),
            active_keys=d.get("active_keys", []),
            revoked_keys=d.get("revoked_keys", []),
            created_at=d.get("created_at", utc_now_iso()),
            commit_id=d.get("commit_id", ""),
            signature=d.get("signature", ""),
        )

    def verify_self(self) -> bool:
        """Verify that agent_id derives from root_public_key."""
        # BUG 5 FIX: validate JWK structure
        if not isinstance(self.root_public_key, dict):
            return False
        if self.root_public_key.get("kty") != "OKP":
            return False
        if self.root_public_key.get("crv") != "Ed25519":
            return False
        x = self.root_public_key.get("x")
        if not isinstance(x, str) or not x:
            return False
        try:
            crypto.b64url_decode(x)
        except Exception:
            return False
        try:
            derived = "did:alethech:" + crypto.b32lower(crypto.sha256(
                canonical_json_bytes(self.root_public_key)
            )[0:16])
            return derived == self.agent_id
        except Exception:
            return False


@dataclass
class ControlEvent(SignedObject):
    """A signed governance event from the root authority.

    Forms a monotonic chain: each event references the hash of the previous one.
    The chain is the source of truth for key authorization state.

    Types of events:
    - key_grant: authorize a new operational key
    - key_revoke: revoke an operational key (compromise)
    - key_rotation: atomically revoke K_old and authorize K_new with cutoff_head
    - migration: declare migration from legacy identity to new identity
    """

    root_id: str = ""
    sequence: int = 1
    previous_control_hash: str = ""  # commit_id of previous ControlEvent, or "" for genesis
    event_type: str = "key_grant"  # key_grant | key_revoke | key_rotation | migration
    key_id: str = ""                # for key_grant, key_revoke: the key being affected
    public_key: dict = field(default_factory=dict)  # for key_grant, key_rotation (new key)
    old_key_id: str = ""            # for key_rotation: the key being replaced
    cutoff_head: str = ""           # for key_rotation: causal marker in commit DAG
    reason: str = "rotation"        # rotation | compromise | expiry | migration
    timestamp: str = field(default_factory=utc_now_iso)
    migration_record_id: str = ""   # for migration events: links to MigrationRecord

    @staticmethod
    def object_type() -> str:
        return "ControlEvent"

    def to_signable_dict(self) -> dict:
        return {
            "type": "ControlEvent",
            "version": 1,
            "root_id": self.root_id,
            "sequence": self.sequence,
            "previous_control_hash": self.previous_control_hash,
            "event_type": self.event_type,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "old_key_id": self.old_key_id,
            "cutoff_head": self.cutoff_head,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "migration_record_id": self.migration_record_id,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["commit_id"] = self.commit_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ControlEvent":
        if d.get("type") != "ControlEvent":
            raise ValueError(f"not a ControlEvent: type={d.get('type')}")
        return cls(
            root_id=d.get("root_id", ""),
            sequence=d.get("sequence", 1),
            previous_control_hash=d.get("previous_control_hash", ""),
            event_type=d.get("event_type", "key_grant"),
            key_id=d.get("key_id", ""),
            public_key=d.get("public_key", {}),
            old_key_id=d.get("old_key_id", ""),
            cutoff_head=d.get("cutoff_head", ""),
            reason=d.get("reason", "rotation"),
            timestamp=d.get("timestamp", utc_now_iso()),
            migration_record_id=d.get("migration_record_id", ""),
            commit_id=d.get("commit_id", ""),
            signature=d.get("signature", ""),
        )


@dataclass
class MigrationRecord(SignedObject):
    """Bilateral migration record: legacy identity → new identity.

    Requires TWO signatures:
    - legacy_signature: signed by the legacy identity's operational key
    - root_signature: signed by the new root authority

    This proves continuity without pretending A == B.
    """

    legacy_agent_id: str = ""  # did:alethech:<H(K1)>
    legacy_public_key: dict = field(default_factory=dict)  # JWK of K1
    new_agent_id: str = ""  # did:alethech:<H(R)>
    new_root_id: str = ""  # did:alethech:root:<H(R)>
    new_root_public_key: dict = field(default_factory=dict)  # JWK of R
    migration_timestamp: str = field(default_factory=utc_now_iso)
    legacy_signature: str = ""  # ed25519:<base64url>  — signature of K1 over canonical bytes
    # root_signature is the standard `signature` field from SignedObject

    @staticmethod
    def object_type() -> str:
        return "MigrationRecord"

    def to_signable_dict(self) -> dict:
        return {
            "type": "MigrationRecord",
            "version": 1,
            "legacy_agent_id": self.legacy_agent_id,
            "legacy_public_key": self.legacy_public_key,
            "new_agent_id": self.new_agent_id,
            "new_root_id": self.new_root_id,
            "new_root_public_key": self.new_root_public_key,
            "migration_timestamp": self.migration_timestamp,
        }

    def to_signed_dict(self) -> dict:
        d = self.to_signable_dict()
        d["commit_id"] = self.commit_id
        d["legacy_signature"] = self.legacy_signature
        d["signature"] = self.signature  # root signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MigrationRecord":
        if d.get("type") != "MigrationRecord":
            raise ValueError(f"not a MigrationRecord: type={d.get('type')}")
        return cls(
            legacy_agent_id=d.get("legacy_agent_id", ""),
            legacy_public_key=d.get("legacy_public_key", {}),
            new_agent_id=d.get("new_agent_id", ""),
            new_root_id=d.get("new_root_id", ""),
            new_root_public_key=d.get("new_root_public_key", {}),
            migration_timestamp=d.get("migration_timestamp", utc_now_iso()),
            legacy_signature=d.get("legacy_signature", ""),
            commit_id=d.get("commit_id", ""),
            signature=d.get("signature", ""),
        )

    def sign_both(self, legacy_keypair: crypto.KeyPair, root_keypair: crypto.KeyPair) -> None:
        """Sign with both the legacy key and the new root key."""
        self.commit_id = self.compute_commit_id()
        msg = self.canonical_bytes_for_signing()
        # Legacy signature
        legacy_sig = legacy_keypair.sign(msg)
        self.legacy_signature = "ed25519:" + crypto.b64url(legacy_sig)
        # Root signature
        root_sig = root_keypair.sign(msg)
        self.signature = "ed25519:" + crypto.b64url(root_sig)

    def verify_both(self, legacy_public_jwk: dict, root_public_jwk: dict) -> bool:
        """Verify both signatures. Returns True only if both pass."""
        if not self.commit_id:
            return False
        if not self.signature.startswith("ed25519:"):
            return False
        if not self.legacy_signature.startswith("ed25519:"):
            return False
        msg = self.canonical_bytes_for_signing()
        try:
            legacy_pub = crypto.KeyPair.public_from_jwk(legacy_public_jwk)
            root_pub = crypto.KeyPair.public_from_jwk(root_public_jwk)
        except Exception:
            return False
        legacy_sig = crypto.b64url_decode(self.legacy_signature[len("ed25519:"):])
        root_sig = crypto.b64url_decode(self.signature[len("ed25519:"):])
        return (crypto.KeyPair.verify(legacy_pub, legacy_sig, msg) and
                crypto.KeyPair.verify(root_pub, root_sig, msg))
