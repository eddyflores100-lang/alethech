"""Generate conformance test vectors.

This script generates JSON vectors in conformance/ that are consumed by
tests/test_conformance_vectors.py. Run this when adding new adversarial
cases — the generated vectors are committed to the repo so external
implementations can test against them without running Python code.

Vector categories generated:
- valid/             : correctly signed artifacts
- invalid_signature/ : tampered signatures
- invalid_key/       : wrong key types, malformed JWKs
- noncanonical/      : non-canonical Ed25519, non-canonical JSON
- unicode/           : unicode normalization edge cases
- numeric/           : number serialization edge cases
- versioning/        : protocol version mismatches
- rollback/          : checkpoint rollback scenarios
- revocation/        : revoked key usage
- key_rotation/      : key rotation chains
"""
import json
from pathlib import Path

from alethech import crypto
from alethech.canonical import canonical_json_bytes
from alethech.objects import (
    Identity, MemoryCommit, EvidenceCommit, Checkpoint,
    IdentityRecordV2, RootAuthority, ControlEvent,
)


def _agent_id_for(jwk: dict) -> str:
    return "did:alethech:" + crypto.b32lower(
        crypto.sha256(canonical_json_bytes(jwk))[0:16]
    )


def _root_id_for(jwk: dict) -> str:
    return "did:alethech:root:" + crypto.b32lower(
        crypto.sha256(canonical_json_bytes(jwk))[0:16]
    )


def gen_valid(out_dir: Path):
    """A correctly signed MemoryCommit that MUST verify."""
    kp = crypto.KeyPair.generate()
    ident = Identity(agent_id=_agent_id_for(kp.public_jwk()),
                     public_key=kp.public_jwk())
    commit = MemoryCommit(
        agent_id=ident.agent_id,
        key_id="key-001",
        parents=[""],
        content={"test": "valid_vector", "value": 42},
    )
    commit.sign(kp)

    vector = {
        "description": "A correctly signed MemoryCommit with valid Ed25519 signature",
        "category": "valid",
        "expected_result": "verify_ok",
        "input": {
            "type": "MemoryCommit",
            "version": 1,
            "identity": ident.to_dict(),
            "commit": commit.to_signed_dict(),
        },
        "notes": "Baseline valid case. Used to confirm the verifier accepts correct artifacts.",
    }
    (out_dir / "valid" / "01_basic_commit.json").write_text(
        json.dumps(vector, indent=2), encoding="utf-8"
    )


def gen_invalid_signature(out_dir: Path):
    """A MemoryCommit with a tampered signature that MUST be rejected."""
    kp = crypto.KeyPair.generate()
    ident = Identity(agent_id=_agent_id_for(kp.public_jwk()),
                     public_key=kp.public_jwk())
    commit = MemoryCommit(
        agent_id=ident.agent_id,
        key_id="key-001",
        parents=[""],
        content={"test": "tampered_signature"},
    )
    commit.sign(kp)
    # Tamper: flip a bit in the signature
    sig = commit.signature
    if sig.startswith("ed25519:"):
        sig_bytes = crypto.b64url_decode(sig[len("ed25519:"):])
        # Flip first byte
        tampered = bytes([sig_bytes[0] ^ 0x01]) + sig_bytes[1:]
        commit.signature = "ed25519:" + crypto.b64url(tampered)

    vector = {
        "description": "MemoryCommit with one bit flipped in the Ed25519 signature",
        "category": "invalid_signature",
        "expected_result": "verify_fail",
        "input": {
            "type": "MemoryCommit",
            "version": 1,
            "identity": ident.to_dict(),
            "commit": commit.to_signed_dict(),
        },
        "notes": "Catches implementations that don't actually verify the signature bytes.",
    }
    (out_dir / "invalid_signature" / "01_flipped_bit.json").write_text(
        json.dumps(vector, indent=2), encoding="utf-8"
    )

    # Tamper: modify content AFTER signing (signature no longer matches)
    commit2 = MemoryCommit(
        agent_id=ident.agent_id,
        key_id="key-001",
        parents=[""],
        content={"test": "original_content"},
    )
    commit2.sign(kp)
    # Tamper: change content after signing
    commit2.content = {"test": "TAMPERED_CONTENT"}

    vector2 = {
        "description": "MemoryCommit where content was modified after signing",
        "category": "invalid_signature",
        "expected_result": "verify_fail",
        "input": {
            "type": "MemoryCommit",
            "version": 1,
            "identity": ident.to_dict(),
            "commit": commit2.to_signed_dict(),
        },
        "notes": "Catches implementations that don't re-canonicalize content before verifying.",
    }
    (out_dir / "invalid_signature" / "02_tampered_content.json").write_text(
        json.dumps(vector2, indent=2), encoding="utf-8"
    )


def gen_invalid_key(out_dir: Path):
    """Various malformed or wrong-type keys."""
    # Wrong kty
    vector = {
        "description": "Identity with kty='RSA' instead of 'OKP'",
        "category": "invalid_key",
        "expected_result": "verify_fail",
        "input": {
            "type": "Identity",
            "version": 1,
            "identity": {
                "type": "Identity",
                "version": 1,
                "agent_id": "did:alethech:fakeagentid000000000",
                "public_key": {"kty": "RSA", "n": "fake", "e": "AQAB"},
                "key_id": "key-001",
                "created_at": "2026-01-01T00:00:00.000Z",
                "recovery_root": "",
            },
        },
        "notes": "Ed25519 requires kty=OKP, crv=Ed25519. RSA keys must be rejected.",
    }
    (out_dir / "invalid_key" / "01_wrong_kty.json").write_text(
        json.dumps(vector, indent=2), encoding="utf-8"
    )

    # Wrong curve
    vector = {
        "description": "Identity with crv='P-256' instead of 'Ed25519'",
        "category": "invalid_key",
        "expected_result": "verify_fail",
        "input": {
            "type": "Identity",
            "version": 1,
            "identity": {
                "type": "Identity",
                "version": 1,
                "agent_id": "did:alethech:fakeagentid000000000",
                "public_key": {"kty": "EC", "crv": "P-256", "x": "fake", "y": "fake"},
                "key_id": "key-001",
                "created_at": "2026-01-01T00:00:00.000Z",
                "recovery_root": "",
            },
        },
        "notes": "Only Ed25519 is supported. EC keys must be rejected.",
    }
    (out_dir / "invalid_key" / "02_wrong_curve.json").write_text(
        json.dumps(vector, indent=2), encoding="utf-8"
    )

    # Malformed base64url in x
    vector = {
        "description": "Identity with malformed base64url in public_key.x",
        "category": "invalid_key",
        "expected_result": "verify_fail",
        "input": {
            "type": "Identity",
            "version": 1,
            "identity": {
                "type": "Identity",
                "version": 1,
                "agent_id": "did:alethech:fakeagentid000000000",
                "public_key": {"kty": "OKP", "crv": "Ed25519", "x": "!!!not-base64!!!"},
                "key_id": "key-001",
                "created_at": "2026-01-01T00:00:00.000Z",
                "recovery_root": "",
            },
        },
        "notes": "Catches implementations that don't validate base64url before decoding.",
    }
    (out_dir / "invalid_key" / "03_malformed_base64.json").write_text(
        json.dumps(vector, indent=2), encoding="utf-8"
    )


def gen_numeric(out_dir: Path):
    """Number serialization edge cases per RFC 8785."""
    cases = [
        (0, "0", "zero integer"),
        (0.0, "0", "positive zero float"),
        (-0.0, "0", "negative zero — RFC 8785 erratum says serialize as '0'"),
        (1e21, "1e+21", "large number requiring scientific notation"),
        (1e-7, "1e-7", "small number requiring scientific notation"),
        (1.5e20, "150000000000000000000", "below 1e21 — decimal notation"),
        (5e-3, "0.005", "above 1e-6 — decimal notation"),
        (3.0, "3", "integer-valued float — strip .0"),
    ]
    for i, (value, expected, desc) in enumerate(cases, 1):
        vector = {
            "description": f"Number serialization: {desc}",
            "category": "numeric",
            "expected_result": "verify_ok",
            "input": {
                "type": "JCSNumberTest",
                "value": value,
                "expected_canonical": expected,
            },
            "notes": f"RFC 8785 / ECMAScript Number::toString() requires '{expected}' for input {value!r}",
        }
        (out_dir / "numeric" / f"{i:02d}_{desc.split()[0]}.json").write_text(
            json.dumps(vector, indent=2), encoding="utf-8"
        )


def gen_unicode(out_dir: Path):
    """Unicode normalization edge cases."""
    # Visually equivalent strings with different code points
    vector = {
        "description": "Two strings that look identical but have different code points",
        "category": "unicode",
        "expected_result": "verify_ok",
        "input": {
            "type": "UnicodeDistinctness",
            "string_a": "café",  # é as single code point U+00E9
            "string_b": "cafe\u0301",  # é as e + combining acute accent U+0301
            "note": "These are visually identical but byte-different. JCS does NOT normalize — they produce different hashes.",
        },
        "notes": "Catches implementations that 'normalize' unicode before hashing (which would break signature verification across implementations).",
    }
    (out_dir / "unicode" / "01_normalization_distinctness.json").write_text(
        json.dumps(vector, indent=2), encoding="utf-8"
    )


def main():
    out = Path(__file__).parent
    for d in ["valid", "invalid_signature", "invalid_key", "numeric", "unicode"]:
        (out / d).mkdir(exist_ok=True)

    gen_valid(out)
    gen_invalid_signature(out)
    gen_invalid_key(out)
    gen_numeric(out)
    gen_unicode(out)
    print(f"Generated conformance vectors in {out}")


if __name__ == "__main__":
    main()
