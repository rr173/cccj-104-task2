"""ORM model.

Device assignment is the per-(device, campaign) rollout ledger row. Its
`install_state` is the single monotonically-progressing FSM variable that all
safety gates key off of; `device_events` is an append-only audit trail with an
idempotency key so duplicate receipts cannot double-count anything.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- device-side install FSM --------------------------------------------------
STATE_REGISTERED = "registered"        # only exists as a device
STATE_ASSIGNED = "assigned"            # seat claimed, nothing downloaded
STATE_DOWNLOADING = "downloading"
STATE_DOWNLOADED = "downloaded"
STATE_INSTALLING = "installing"        # critical region: flash writes started
STATE_INSTALLED = "installed"          # confirmed boot on new firmware
STATE_FAILED = "failed"                # install failed, device rolled back
STATE_ROLLED_BACK = "rolled_back"      # explicit rollback completion receipt

# Terminal states (no further offers for this campaign)
TERMINAL_STATES = frozenset({STATE_INSTALLED, STATE_FAILED})
# Past download gate: pause must not strand a device mid-flash.
PAST_DOWNLOAD_STATES = frozenset({STATE_DOWNLOADED, STATE_INSTALLING})
# Critical region: device must be allowed to finish / roll back safely.
CRITICAL_STATES = frozenset({STATE_INSTALLING})

# Forward-only transitions accepted from device receipts.
ALLOWED_TRANSITIONS: dict[str, frozenset[str, ...]] = {
    STATE_ASSIGNED: frozenset({STATE_DOWNLOADING}),
    STATE_DOWNLOADING: frozenset({STATE_DOWNLOADED, STATE_ASSIGNED}),
    STATE_DOWNLOADED: frozenset({STATE_INSTALLING}),
    STATE_INSTALLING: frozenset({STATE_INSTALLED, STATE_FAILED, STATE_ROLLED_BACK}),
}

# --- rollout batch lifecycle --------------------------------------------------
BATCH_PENDING = "pending"
BATCH_ACTIVE = "active"
BATCH_PAUSED = "paused"     # operator hold; resumable
BATCH_HALTED = "halted"     # auto stop or kill switch; resumable only explicitly
BATCH_COMPLETE = "complete"

BATCH_OPEN_STATES = frozenset({BATCH_ACTIVE})
BATCH_NON_TERMINAL = frozenset({BATCH_PENDING, BATCH_ACTIVE, BATCH_PAUSED, BATCH_HALTED})


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    hardware_batch: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    bootloader: Mapped[str] = mapped_column(String(64), nullable=False)
    current_version: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    assignments: Mapped[list["Assignment"]] = relationship(back_populates="device")


class Image(Base):
    __tablename__ = "images"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    min_bootloader: Mapped[str | None] = mapped_column(String(64), nullable=True)
    max_bootloader: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    chunk_size: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("model", "version", name="uq_image_model_version"),)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    image_id: Mapped[str] = mapped_column(ForeignKey("images.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    batches: Mapped[list["Batch"]] = relationship(back_populates="campaign")


class Batch(Base):
    """A staged rollout targeting one hardware batch. Children are the next
    stages; pausing/halting cascades through descendants so diffusion stops
    along the whole staged path."""
    __tablename__ = "batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False, index=True)
    hardware_batch: Mapped[str] = mapped_column(String(128), nullable=False)
    stage: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # quota_mode: 'absolute' -> quota seats; 'percent' -> % of fleet of the hw batch
    quota_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="absolute")
    quota_value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default=BATCH_PENDING)
    failure_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    failure_min_sample: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("batches.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    campaign: Mapped[Campaign] = relationship(back_populates="batches")

    __table_args__ = (
        UniqueConstraint("campaign_id", "hardware_batch", "stage", name="uq_batch_campaign_hw_stage"),
        CheckConstraint("quota_mode in ('absolute','percent')", name="ck_batch_quota_mode"),
    )


class Assignment(Base):
    __tablename__ = "assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), nullable=False, index=True)
    install_state: Mapped[str] = mapped_column(String(16), nullable=False, default=STATE_ASSIGNED)
    offered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    fail_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    active_slot: Mapped[str] = mapped_column(String(16), nullable=False, default="A")

    device: Mapped[Device] = relationship(back_populates="assignments")

    __table_args__ = (
        UniqueConstraint("device_id", "campaign_id", name="uq_assignment_device_campaign"),
        Index("ix_assignment_batch_state", "batch_id", "install_state"),
    )


class DeviceEvent(Base):
    __tablename__ = "device_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    assignment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("device_id", "idempotency_key", name="uq_event_device_idem"),
    )


# --- signed release trust -----------------------------------------------------
# Root version lifecycle. A rotation is written committed in ONE transaction:
# there is deliberately no long-lived intermediate state, so a crash can never
# expose a half-applied root. The state column exists to make the two-phase
# intent explicit and to reject stray rows in audits.
ROOT_PENDING = "pending"
ROOT_COMMITTED = "committed"
ROOT_SUPERSEDED = "superseded"


class TrustRoot(Base):
    """One versioned, signed root document for a device model.

    v1 is the trust anchor (registered out of band); each subsequent row is a
    dual-authorized transition (signed by both the retiring and the incoming
    root key). Devices walk committed versions consecutively.
    """
    __tablename__ = "trust_roots"

    model: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    envelope: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default=ROOT_COMMITTED)
    idempotency_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("model", "idempotency_key", name="uq_root_model_idem"),
        Index("ix_trust_root_model_state", "model", "state"),
    )


class ReleaseSignature(Base):
    """Deterministically serialized, signed metadata for one image.

    ``counter`` is the per-model monotonically increasing security counter a
    device uses for downgrade resistance; (model, version) and (model, counter)
    are unique so two different binaries can never claim the same release
    version and trust state can never be lowered.
    """
    __tablename__ = "release_signatures"

    image_id: Mapped[str] = mapped_column(
        ForeignKey("images.id"), primary_key=True
    )
    model: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    counter: Mapped[int] = mapped_column(Integer, nullable=False)
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    keyid: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("model", "version", name="uq_release_model_version"),
        UniqueConstraint("model", "counter", name="uq_release_model_counter"),
        UniqueConstraint("model", "idempotency_key", name="uq_release_model_idem"),
    )


class DeviceTrustState(Base):
    """Durable per-device anti-rollback watermark. Survives process restarts:
    a release whose signed counter is not strictly above ``highest_counter``
    is refused before any critical write."""
    __tablename__ = "device_trust_state"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    root_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    highest_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class FailureReceipt(Base):
    """Durable, queryable record of a release/trust rejection.

    Written when a device refuses content BEFORE the critical write phase, so
    the active boot slot is untouched. Retries carry the same stable
    idempotency key and therefore converge to this single row.
    """
    __tablename__ = "failure_receipts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    assignment_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    image_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    image_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    counter_seen: Mapped[int | None] = mapped_column(Integer, nullable=True)
    root_version_seen: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Stable machine-readable TrustError reason (release_expired, revoked_signer,
    # counter_rollback, artifact_digest_mismatch, root_chain_gap, ...).
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    # Where in the pipeline rejection happened (checkin/download/pre_flash).
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="pre_flash")
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("device_id", "idempotency_key", name="uq_receipt_device_idem"),
        Index("ix_receipt_device_created", "device_id", "created_at"),
        Index("ix_receipt_reason", "reason"),
    )
