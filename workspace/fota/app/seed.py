"""Idempotent demo seed: one image/campaign for HW2026Q3 terminals."""
from __future__ import annotations

import os
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import storage
from .models import BATCH_PENDING, Batch, Campaign, Image

DEMO_MODEL = os.environ.get("DEMO_MODEL", "term-x1")
DEMO_VERSION = os.environ.get("DEMO_VERSION", "2.0.0")
DEMO_HW = os.environ.get("DEMO_HW", "HW2026Q3")


def _demo_firmware() -> bytes:
    # Deterministic pseudo-firmware (~600 KiB, ~3 chunks at 256 KiB blocks).
    size = 600_000
    pattern = bytes((i * 31 + 7) % 256 for i in range(256))
    reps = size // len(pattern) + 1
    return (pattern * reps)[:size]


def seed_if_empty(db: Session) -> None:
    if db.scalar(select(Image).where(Image.model == DEMO_MODEL)):
        return
    stored = storage.save_blob(_demo_firmware())
    img = Image(
        id=str(uuid.uuid4()),
        model=DEMO_MODEL,
        version=DEMO_VERSION,
        min_bootloader="1.0.0",
        max_bootloader="1.99.0",
        size=stored.size,
        sha256=stored.sha256,
        chunk_size=stored.chunk_size,
        chunk_count=stored.chunk_count,
    )
    db.add(img)
    db.flush()
    camp = Campaign(id=str(uuid.uuid4()), name=f"demo-{DEMO_MODEL}-{DEMO_VERSION}", image_id=img.id)
    db.add(camp)
    db.flush()
    canary = Batch(
        id=str(uuid.uuid4()),
        campaign_id=camp.id,
        hardware_batch=DEMO_HW,
        stage=1,
        quota_mode="absolute",
        quota_value=2,
        failure_threshold=0.5,
        failure_min_sample=3,
        parent_id=None,
        state=BATCH_PENDING,
    )
    db.add(canary)
    db.commit()
