"""Pydantic v2 schemas for the HTTP API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ----- device side -----
class RegisterIn(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    model: str
    hardware_batch: str
    bootloader: str
    current_version: str


class ChunkOut(BaseModel):
    index: int
    sha256: str
    offset: int
    size: int


class OfferOut(BaseModel):
    assignment_id: str
    campaign_id: str
    batch_id: str
    image_id: str
    image_sha256: str
    version: str
    size: int
    chunk_size: int
    chunks: list[ChunkOut]
    finalize_only: bool
    install_state: str
    # Signed release metadata (canonical JSON envelope). The terminal MUST
    # verify it against its pinned root before entering the critical phase.
    signed_release: dict[str, Any]
    # Counter the device persists as its anti-rollback watermark on success.
    security_counter: int
    expires_at: datetime
    root_version: int


class CheckInResponse(BaseModel):
    device_id: str
    offered: bool
    reason: str | None = None
    offer: OfferOut | None = None
    server_time: datetime
    # Trust view delivered alongside every check-in: current root version and
    # the consecutive envelopes a returning device needs to catch up.
    root_version: int | None = None
    root_updates: list[dict[str, Any]] = Field(default_factory=list)


class EventIn(BaseModel):
    assignment_id: str
    event_type: str
    idempotency_key: str = Field(min_length=8, max_length=120)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    duplicate: bool
    applied: bool
    from_state: str | None = None
    to_state: str | None = None
    halted_batch_ids: list[str] = Field(default_factory=list)


class RejectionIn(BaseModel):
    """Device-reported durable failure receipt for a release rejected BEFORE
    the critical write. The idempotency key is stable per
    (device, release, rejection-kind), so a retry converges to one row."""
    assignment_id: str | None = None
    reason: str = Field(min_length=3, max_length=64)
    stage: str = Field(default="pre_flash", max_length=32)
    idempotency_key: str = Field(min_length=8, max_length=120)
    image_id: str | None = None
    image_sha256: str | None = None
    model: str | None = None
    version: str | None = None
    counter_seen: int | None = None
    root_version_seen: int | None = None
    detail: str | None = Field(default=None, max_length=2000)


class RejectionOut(BaseModel):
    id: str
    duplicate: bool
    reason: str
    stage: str
    created_at: datetime


# ----- admin side -----
class ImageOut(BaseModel):
    id: str
    model: str
    version: str
    min_bootloader: str | None
    max_bootloader: str | None
    size: int
    sha256: str
    chunk_size: int
    chunk_count: int
    created_at: datetime


class CampaignIn(BaseModel):
    name: str
    image_id: str


class CampaignOut(BaseModel):
    id: str
    name: str
    image_id: str
    created_at: datetime


class BatchIn(BaseModel):
    campaign_id: str
    hardware_batch: str
    stage: int = Field(ge=1, default=1)
    quota_mode: Literal["absolute", "percent"] = "absolute"
    quota_value: int = Field(ge=0, default=0)
    failure_threshold: float | None = Field(default=None, ge=0, le=1)
    failure_min_sample: int | None = Field(default=None, ge=1)
    parent_id: str | None = None


class BatchOut(BaseModel):
    id: str
    campaign_id: str
    hardware_batch: str
    stage: int
    quota_mode: str
    quota_value: int
    state: str
    failure_threshold: float
    failure_min_sample: int
    parent_id: str | None
    created_at: datetime
    stats: dict[str, Any] | None = None


class BatchActionIn(BaseModel):
    action: Literal["activate", "pause", "halt", "resume", "complete"]
    force: bool = False


class DeviceOut(BaseModel):
    id: str
    model: str
    hardware_batch: str
    bootloader: str
    current_version: str
    last_seen: datetime


# ----- trust / signing (admin side) -----
class GenesisIn(BaseModel):
    model: str
    expires_at: datetime | None = None
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=120)


class RotateRootIn(BaseModel):
    model: str
    expires_at: datetime | None = None
    revoke_signer_ids: list[str] = Field(default_factory=list)
    add_signer: bool = True
    idempotency_key: str = Field(min_length=8, max_length=120)


class TrustRootOut(BaseModel):
    model: str
    version: int
    state: str
    root_key_ids: list[str] = Field(default_factory=list)
    signers: dict[str, str] = Field(default_factory=dict)
    expires: datetime | None = None
    envelope: dict[str, Any]
    duplicate: bool = False


class SignReleaseIn(BaseModel):
    """Sign an already-uploaded image using the offline keyring."""
    image_id: str
    signer: Literal["delegated", "root"] = "delegated"
    root_version: int | None = None
    counter: int | None = Field(default=None, ge=0)
    expires_at: datetime | None = None
    ttl_days: int | None = Field(default=None, ge=1)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=120)


class PublishSignedIn(BaseModel):
    """Publish metadata signed on an air-gapped machine (offline workflow)."""
    image_id: str
    envelope: dict[str, Any]
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=120)


class ReleaseSignatureOut(BaseModel):
    image_id: str
    model: str
    version: str
    counter: int
    expires: datetime
    keyid: str
    duplicate: bool = False
    envelope: dict[str, Any]


class FailureReceiptOut(BaseModel):
    id: str
    device_id: str
    assignment_id: str | None
    model: str | None
    image_id: str | None
    image_sha256: str | None
    version: str | None
    counter_seen: int | None
    root_version_seen: int | None
    reason: str
    stage: str
    detail: str | None
    resolved: bool
    idempotency_key: str
    created_at: datetime
