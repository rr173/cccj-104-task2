"""Ed25519 signing/verification with base64url key + signature encoding.

Ed25519 is deliberately chosen for an offline signing workflow: keys are
32 bytes (one file / one line), signing is non-deterministic-input safe, there
is no parameter negotiation, and a signature is exactly 64 bytes — cheap for
an MCU-class terminal to verify.
"""
from __future__ import annotations

import base64
import dataclasses

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


class BadSignature(Exception):
    """Signature bytes malformed or not made by the claimed public key."""


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    if isinstance(text, bytes):
        text = text.decode("ascii")
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


@dataclasses.dataclass(frozen=True)
class SigningKey:
    """Offline signing key. ``seed_b64`` is the secret; treat it as such."""

    seed_b64: str
    public_b64: str

    @classmethod
    def generate(cls) -> "SigningKey":
        return from_private(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed_b64: str) -> "SigningKey":
        key = _load_private(seed_b64)
        return from_private(key)

    def sign(self, message: bytes) -> str:
        return b64e(_load_private(self.seed_b64).sign(message))

    def private_pem(self) -> bytes:
        return _load_private(self.seed_b64).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )


def from_private(key: Ed25519PrivateKey) -> SigningKey:
    seed = key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return SigningKey(b64e(seed), b64e(pub))


def from_seed_bytes(raw_seed: bytes) -> SigningKey:
    """Deterministic key from a 32-byte seed (used for idempotent rotation
    retries that must regenerate identical incoming material)."""
    if len(raw_seed) != 32:
        raise ValueError("ed25519 raw seed must be 32 bytes")
    return from_private(Ed25519PrivateKey.from_private_bytes(raw_seed))


def generate_keypair() -> SigningKey:
    return SigningKey.generate()


def _load_private(seed_b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64d(seed_b64))


def _load_public(public_b64: str) -> Ed25519PublicKey:
    raw = b64d(public_b64)
    if len(raw) != 32:
        raise BadSignature(f"ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign(seed_b64: str, message: bytes) -> str:
    return b64e(_load_private(seed_b64).sign(message))


def verify(public_b64: str, signature_b64: str, message: bytes) -> bool:
    """Return True on a valid signature; False on any malformed/invalid one.

    Verification failures must never raise into the caller's face: on a
    terminal a bad signature is a *policy* result ("reject this release"),
    not an exceptional crash.
    """
    try:
        _load_public(public_b64).verify(b64d(signature_b64), message)
    except (BadSignature, InvalidSignature, ValueError):
        return False
    return True
