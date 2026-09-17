"""Offline release signing, root-key rotation and anti-rollback primitives.

Pure logic only (no DB / FastAPI imports) so the exact same verification code
can run both inside the service and on a terminal.
"""
from __future__ import annotations

from .canonical import canonical_bytes
from .keys import (
    BadSignature,
    SigningKey,
    b64d,
    b64e,
    generate_keypair,
    sign,
    verify,
)
from .metadata import (
    RELEASE_DOCUMENT_TYPE,
    ROOT_DOCUMENT_TYPE,
    SIGNER_ACTIVE,
    SIGNER_REVOKED,
    ReleaseClaims,
    RootView,
    TrustError,
    build_release_envelope,
    build_root_envelope,
    key_id,
    normalize_root,
    verify_release_envelope,
    verify_root_envelope,
)

# Shorthand used by device-side verification.
verify_release = verify_release_envelope

__all__ = [
    "canonical_bytes",
    "BadSignature",
    "SigningKey",
    "b64d",
    "b64e",
    "generate_keypair",
    "key_id",
    "sign",
    "verify",
    "RELEASE_DOCUMENT_TYPE",
    "ROOT_DOCUMENT_TYPE",
    "SIGNER_ACTIVE",
    "SIGNER_REVOKED",
    "ReleaseClaims",
    "RootView",
    "TrustError",
    "build_release_envelope",
    "build_root_envelope",
    "normalize_root",
    "verify_release_envelope",
    "verify_root_envelope",
    "verify_release",
]
