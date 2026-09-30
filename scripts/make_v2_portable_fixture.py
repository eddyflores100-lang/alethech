"""Build a minimal, fully verified V2 store for portable/browser conformance."""
from __future__ import annotations
import sys
from pathlib import Path

from alethech import crypto
from alethech.api import Alethech
from alethech.canonical import canonical_json_bytes
from alethech.container import seal_store
from alethech.objects import Checkpoint, ControlEvent, IdentityRecordV2, MemoryCommit, RootAuthority
from alethech.store import Store
from alethech.verify import verify_store


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_v2_portable_fixture.py <store-dir> <out.aleth>")
    root_path = Path(sys.argv[1])
    output = Path(sys.argv[2])

    store = Store.init(root_path)
    root_key = crypto.KeyPair.generate()
    signing_key = crypto.KeyPair.generate()

    root_jwk = root_key.public_jwk()
    signing_jwk = signing_key.public_jwk()
    digest = crypto.sha256(canonical_json_bytes(root_jwk))[0:16]
    suffix = crypto.b32lower(digest)
    root_id = "did:alethech:root:" + suffix
    agent_id = "did:alethech:" + suffix

    root = RootAuthority(
        root_id=root_id,
        root_public_key=root_jwk,
        recovery_quorum={"type": "single", "threshold": 1, "members": []},
    )
    root.sign(root_key)
    store.write_root_authority(root)

    grant = ControlEvent(
        root_id=root_id,
        sequence=1,
        previous_control_hash="",
        event_type="key_grant",
        key_id="key-001",
        public_key=signing_jwk,
        reason="fixture",
    )
    grant.sign(root_key)
    store.write_control_event(grant)

    identity = IdentityRecordV2(
        agent_id=agent_id,
        root_id=root_id,
        root_public_key=root_jwk,
        active_keys=[{
            "key_id": "key-001",
            "public_key": signing_jwk,
            "authorized_by": grant.commit_id,
            "authorized_at": grant.timestamp,
            "expires_at": None,
        }],
        revoked_keys=[],
    )
    identity.sign(root_key)
    store.write_identity_record_v2(identity)
    store.write_signing_key(signing_key)

    genesis = MemoryCommit(
        agent_id=agent_id,
        key_id="key-001",
        parents=[],
        session_id="v2-fixture",
        memory_type="semantic",
        content={"type": "genesis"},
        provenance={
            "source": "agent_observation",
            "source_id": None,
            "evidence_refs": [],
            "confidence": 1.0,
        },
    )
    genesis.sign(signing_key)
    store.write_commit(genesis)
    store.write_head(genesis.commit_id)

    api = Alethech(store)
    ev = api.evidence(
        tool="v2.fixture",
        input_bytes=b"request",
        output_bytes=b"response",
        artifacts={"proof.bin": b"v2-portable-proof"},
    )
    api.commit(
        {"interop": "v2-browser"},
        evidence_refs=[ev.commit_id],
        session_id="v2-fixture",
    )

    checkpoint = Checkpoint(
        agent_id=agent_id,
        head_commit_id=store.read_head() or "",
        commit_count=len(store.load_commits()),
        evidence_count=len(store.load_evidence()),
        sequence=1,
        key_id="key-001",
    )
    checkpoint.sign(signing_key)
    checkpoints_dir = store.root / "checkpoints"
    checkpoints_dir.mkdir(exist_ok=True)
    import json
    (checkpoints_dir / "v2.checkpoint.json").write_text(
        json.dumps(checkpoint.to_signed_dict(), indent=2),
        encoding="utf-8",
    )

    report = verify_store(store)
    if not report.ok:
        raise SystemExit(report.summary())
    seal_store(store, output, "v2-passphrase")


if __name__ == "__main__":
    main()
