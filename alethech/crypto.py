"""Cryptographic primitives: Ed25519, SHA-256, base64url, base32.

No ambiguity. No LLM. No blockchain. Just bytes.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------- encoding helpers ----------

def b64url(data: bytes) -> str:
    """base64 URL-safe encoding, no padding (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """base64 URL-safe decoding, tolerant to padding presence."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b32lower(data: bytes) -> str:
    """base32 lowercase, no padding (RFC 4648 §6, lowercase variant)."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


# ---------- SHA-256 ----------

def sha256(data: bytes) -> bytes:
    """SHA-256 digest, raw 32 bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 digest as lowercase hex string."""
    return sha256(data).hex()


# ---------- Ed25519 ----------

@dataclass
class KeyPair:
    """An Ed25519 key pair, with serialization helpers."""

    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = Ed25519PrivateKey.generate()
        return cls(private=sk, public=sk.public_key())

    # --- public key in JWK format (RFC 7517) ---

    def public_jwk(self) -> dict:
        """Return the public key as a JWK dict (OKP / Ed25519)."""
        pub_bytes = self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url(pub_bytes),
        }

    @staticmethod
    def public_bytes_from_jwk(jwk: dict) -> bytes:
        """Extract raw 32-byte public key from JWK dict."""
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError(f"not an Ed25519 JWK: kty={jwk.get('kty')} crv={jwk.get('crv')}")
        x = jwk.get("x")
        if not isinstance(x, str):
            raise ValueError("JWK missing 'x' field")
        return b64url_decode(x)

    # --- private key serialization (PEM) ---

    def private_pem(self) -> bytes:
        return self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_private_pem(cls, pem: bytes) -> "KeyPair":
        sk = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(sk, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        return cls(private=sk, public=sk.public_key())

    # --- sign / verify ---

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)

    @staticmethod
    def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
        try:
            public_key.verify(signature, message)
            return True
        except Exception:
            return False

    @staticmethod
    def public_from_jwk(jwk: dict) -> Ed25519PublicKey:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _P
        return _P.from_public_bytes(KeyPair.public_bytes_from_jwk(jwk))


# ---------- agent_id derivation (corrección 1 de GPT) ----------

def derive_agent_id(public_jwk: dict) -> str:
    """agent_id = 'did:alethech:' + base32(sha256(canonical_jwk)[0:16]).

    The public key in JWK form is canonicalized via JCS, hashed with SHA-256,
    and the first 16 bytes (128 bits) are encoded in base32 lowercase.
    """
    from .canonical import canonical_json_bytes
    pk_canonical = canonical_json_bytes(public_jwk)
    pk_hash = sha256(pk_canonical)
    return "did:alethech:" + b32lower(pk_hash[0:16])
