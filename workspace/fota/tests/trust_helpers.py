"""Helpers for the signed-release acceptance suite.

Expose the offline signer's Ed25519 material (the service keyring) so tests
can construct genuinely-signed-but-policy-bad metadata: old-root signatures,
revoked signers, expired documents, counters that roll back, tampered
envelopes. Everything a real air-gapped signing workstation would do.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import config
from app.security import (
    SigningKey,
    build_release_envelope,
    key_id,
)

FUTURE = datetime(2100, 1, 1, tzinfo=timezone.utc)
PAST = datetime(2000, 1, 1, tzinfo=timezone.utc)


def keyring() -> dict:
    p = config.KEYS_ROOT / "keyring.json"
    return json.loads(p.read_text()) if p.exists() else {"roots": {}, "signers": {}}


def root_key(model: str, version: int = 1) -> SigningKey:
    return SigningKey.from_seed(keyring()["roots"][model][f"v{version}"]["seed"])


def signer_key(model: str, alias: str = "primary") -> SigningKey:
    return SigningKey.from_seed(keyring()["signers"][model][alias]["seed"])


def release_envelope(
    *,
    model: str,
    sha256: str,
    version: str,
    counter: int,
    signer: SigningKey,
    expires: datetime = FUTURE,
) -> dict:
    return build_release_envelope(
        model=model,
        artifact_digest="sha256:" + sha256,
        version=version,
        counter=counter,
        expires=expires,
        signer=signer,
    )


def setup_campaign(client, admin, *, model="term-x1", version="2.0.0",
                   quota=10, hw="HW1", blob_seed=b"FW-2.0", size=200):
    """Upload (auto-signed), campaign, batch, activate. Returns ids + blob."""
    img, blob = admin.upload_image(model=model, version=version,
                                   blob_seed=blob_seed, size=size)
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], hardware_batch=hw, quota_value=quota)
    admin.action(b["id"], "activate")
    return {"img": img, "blob": blob, "camp": camp, "batch": b}
