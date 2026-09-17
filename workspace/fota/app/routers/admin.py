"""Operator-facing API: images, campaigns, staged batches, fleet/debug views."""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, rollout, storage, trust
from ..db import get_session
from ..models import (
    Assignment,
    Batch,
    Campaign,
    Device,
    DeviceEvent,
    FailureReceipt,
    Image,
    ReleaseSignature,
    TrustRoot,
    utcnow,
)
from ..schemas import (
    BatchActionIn,
    BatchIn,
    BatchOut,
    CampaignIn,
    CampaignOut,
    DeviceOut,
    FailureReceiptOut,
    GenesisIn,
    ImageOut,
    PublishSignedIn,
    RegisterIn,
    ReleaseSignatureOut,
    RotateRootIn,
    SignReleaseIn,
    TrustRootOut,
)
from ..security import normalize_root

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _batch_out(db: Session, b: Batch) -> BatchOut:
    return BatchOut(
        id=b.id,
        campaign_id=b.campaign_id,
        hardware_batch=b.hardware_batch,
        stage=b.stage,
        quota_mode=b.quota_mode,
        quota_value=b.quota_value,
        state=b.state,
        failure_threshold=b.failure_threshold,
        failure_min_sample=b.failure_min_sample,
        parent_id=b.parent_id,
        created_at=b.created_at,
        stats=rollout.batch_stats(db, b.id),
    )


# ----- images -----
@router.post("/images", response_model=ImageOut, status_code=status.HTTP_201_CREATED)
async def upload_image(
    file: UploadFile = File(...),
    model: str = Form(...),
    version: str = Form(...),
    min_bootloader: str | None = Form(default=None),
    max_bootloader: str | None = Form(default=None),
    sign: bool = Form(default=True),
    db: Session = Depends(get_session),
) -> ImageOut:
    data = await file.read()
    stored = storage.save_blob(data)
    existing = db.scalar(select(Image).where(Image.sha256 == stored.sha256))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"image_exists:{existing.id}")
    dup_v = db.scalar(select(Image).where(Image.model == model, Image.version == version))
    if dup_v is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "model_version_exists")
    img = Image(
        id=str(uuid.uuid4()),
        model=model,
        version=version,
        min_bootloader=min_bootloader,
        max_bootloader=max_bootloader,
        size=stored.size,
        sha256=stored.sha256,
        chunk_size=stored.chunk_size,
        chunk_count=stored.chunk_count,
    )
    db.add(img)
    db.commit()
    db.refresh(img)
    # Every released artifact carries signed metadata. The first image for a
    # model also bootstraps the v1 trust anchor (the demo convenience; in
    # production genesis is created explicitly out of band before devices ship).
    if sign:
        try:
            trust.ensure_genesis(db, model)
            trust.sign_release(db, img)
        except trust.TrustConflict as e:
            raise HTTPException(status.HTTP_409_CONFLICT, e.reason)
    return img  # type: ignore[return-value]


@router.get("/images", response_model=list[ImageOut])
def list_images(db: Session = Depends(get_session)):
    return db.scalars(select(Image).order_by(Image.created_at.desc())).all()


# ----- campaigns -----
@router.post("/campaigns", response_model=CampaignOut, status_code=status.HTTP_201_CREATED)
def create_campaign(body: CampaignIn, db: Session = Depends(get_session)) -> CampaignOut:
    if db.get(Image, body.image_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "image_not_found")
    c = Campaign(id=str(uuid.uuid4()), name=body.name, image_id=body.image_id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(db: Session = Depends(get_session)):
    return db.scalars(select(Campaign).order_by(Campaign.created_at.desc())).all()


# ----- batches (staged rollout) -----
@router.post("/batches", response_model=BatchOut, status_code=status.HTTP_201_CREATED)
def create_batch(body: BatchIn, db: Session = Depends(get_session)) -> BatchOut:
    if db.get(Campaign, body.campaign_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "campaign_not_found")
    if body.parent_id is not None and db.get(Batch, body.parent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "parent_batch_not_found")
    dup = db.scalar(
        select(Batch).where(
            Batch.campaign_id == body.campaign_id,
            Batch.hardware_batch == body.hardware_batch,
            Batch.stage == body.stage,
        )
    )
    if dup is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "batch_stage_exists")
    b = Batch(
        id=str(uuid.uuid4()),
        campaign_id=body.campaign_id,
        hardware_batch=body.hardware_batch,
        stage=body.stage,
        quota_mode=body.quota_mode,
        quota_value=body.quota_value,
        failure_threshold=(
            body.failure_threshold
            if body.failure_threshold is not None
            else config.FAILURE_THRESHOLD
        ),
        failure_min_sample=(
            body.failure_min_sample
            if body.failure_min_sample is not None
            else config.FAILURE_MIN_SAMPLE
        ),
        parent_id=body.parent_id,
    )
    db.add(b)
    db.commit()
    db.refresh(b)
    return _batch_out(db, b)


@router.get("/batches", response_model=list[BatchOut])
def list_batches(campaign_id: str | None = None, db: Session = Depends(get_session)):
    q = select(Batch).order_by(Batch.stage.asc(), Batch.created_at.asc())
    if campaign_id:
        q = q.where(Batch.campaign_id == campaign_id)
    return [_batch_out(db, b) for b in db.scalars(q).all()]


@router.get("/batches/{batch_id}", response_model=BatchOut)
def get_batch(batch_id: str, db: Session = Depends(get_session)) -> BatchOut:
    b = db.get(Batch, batch_id)
    if b is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "batch_not_found")
    return _batch_out(db, b)


@router.post("/batches/{batch_id}/action", response_model=BatchOut)
def batch_action(
    batch_id: str, body: BatchActionIn, db: Session = Depends(get_session)
) -> BatchOut:
    try:
        b = rollout.set_batch_state(db, batch_id, body.action, force=body.force)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "batch_not_found")
    except PermissionError:
        raise HTTPException(status.HTTP_409_CONFLICT, "force_required_to_resume_halted")
    except rollout.StateError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad_action")
    return _batch_out(db, b)


# ----- fleet / debug -----
@router.post("/devices", response_model=DeviceOut)
def upsert_device(body: RegisterIn, db: Session = Depends(get_session)) -> DeviceOut:
    d = db.get(Device, body.id)
    if d is None:
        d = Device(id=body.id, last_seen=utcnow())
        db.add(d)
    d.model, d.hardware_batch, d.bootloader, d.current_version = (
        body.model,
        body.hardware_batch,
        body.bootloader,
        body.current_version,
    )
    db.commit()
    db.refresh(d)
    return d


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    hardware_batch: str | None = None,
    model: str | None = None,
    db: Session = Depends(get_session),
):
    q = select(Device)
    if hardware_batch:
        q = q.where(Device.hardware_batch == hardware_batch)
    if model:
        q = q.where(Device.model == model)
    return db.scalars(q.order_by(Device.id)).all()


@router.get("/assignments")
def list_assignments(batch_id: str | None = None, db: Session = Depends(get_session)):
    q = select(Assignment)
    if batch_id:
        q = q.where(Assignment.batch_id == batch_id)
    out = []
    for a in db.scalars(q.order_by(Assignment.offered_at)).all():
        out.append(
            {
                "id": a.id,
                "device_id": a.device_id,
                "batch_id": a.batch_id,
                "campaign_id": a.campaign_id,
                "install_state": a.install_state,
                "fail_reason": a.fail_reason,
                "active_slot": a.active_slot,
                "updated_at": a.updated_at,
            }
        )
    return out


@router.get("/events")
def all_events(
    batch_id: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_session),
):
    q = select(DeviceEvent).order_by(DeviceEvent.id.desc()).limit(min(limit, 1000))
    if batch_id:
        ids = select(Assignment.id).where(Assignment.batch_id == batch_id)
        q = q.where(DeviceEvent.assignment_id.in_(ids))
    return [
        {
            "id": e.id,
            "device_id": e.device_id,
            "event_type": e.event_type,
            "idempotency_key": e.idempotency_key,
            "from_state": e.from_state,
            "to_state": e.to_state,
            "duplicate": e.duplicate,
            "created_at": e.created_at,
        }
        for e in db.scalars(q).all()
    ]


# ----- trust authority: genesis, rotation, signed releases, receipts -----
def _trust_root_out(row: TrustRoot, *, duplicate: bool = False) -> TrustRootOut:
    envelope = json.loads(row.envelope)
    view = normalize_root(envelope["signed"])
    return TrustRootOut(
        model=row.model,
        version=row.version,
        state=row.state,
        root_key_ids=sorted(view.root_keys),
        signers={k: v["state"] for k, v in view.signers.items()},
        expires=view.expires,
        envelope=envelope,
        duplicate=duplicate,
    )


@router.post("/trust/genesis", response_model=TrustRootOut, status_code=status.HTTP_201_CREATED)
def create_genesis(body: GenesisIn, db: Session = Depends(get_session)) -> TrustRootOut:
    try:
        row, created = trust.ensure_genesis(
            db, body.model, expires=body.expires_at, idempotency_key=body.idempotency_key
        )
    except trust.TrustError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, e.reason)
    return _trust_root_out(row, duplicate=not created)


@router.post("/trust/rotate", response_model=TrustRootOut)
def rotate_root(body: RotateRootIn, db: Session = Depends(get_session)) -> TrustRootOut:
    """Dual-authorized root-key rotation (old + new root sign). Committed in a
    single transaction; retrying the same idempotency key converges."""
    try:
        row, created = trust.rotate_root(
            db,
            body.model,
            expires=body.expires_at,
            revoke_signer_ids=body.revoke_signer_ids,
            add_signer=body.add_signer,
            idempotency_key=body.idempotency_key,
        )
    except trust.TrustError as e:
        code = status.HTTP_404_NOT_FOUND if e.reason == "no_genesis" else status.HTTP_400_BAD_REQUEST
        raise HTTPException(code, e.reason)
    return _trust_root_out(row, duplicate=not created)


@router.get("/trust/{model}/roots", response_model=list[TrustRootOut])
def list_roots(model: str, db: Session = Depends(get_session)):
    rows = db.scalars(
        select(TrustRoot).where(TrustRoot.model == model).order_by(TrustRoot.version.asc())
    ).all()
    return [_trust_root_out(r) for r in rows]


@router.get("/trust/{model}/status")
def trust_status(model: str, db: Session = Depends(get_session)):
    st = trust.genesis_status(db, model)
    if st is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no_trust_anchor")
    return st


@router.post("/releases/sign", response_model=ReleaseSignatureOut)
def sign_release(body: SignReleaseIn, db: Session = Depends(get_session)) -> ReleaseSignatureOut:
    img = db.get(Image, body.image_id)
    if img is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "image_not_found")
    try:
        if body.signer == "root":
            rv = body.root_version
            if rv is None:
                latest = trust.latest_committed_root(db, img.model)
                rv = latest.version if latest else 1
            row, created = trust.sign_release_with_root_key(
                db, img, root_version=rv, counter=body.counter,
                expires=body.expires_at, idempotency_key=body.idempotency_key,
            )
        else:
            kwargs = dict(counter=body.counter, expires=body.expires_at,
                          idempotency_key=body.idempotency_key)
            if body.ttl_days is not None:
                kwargs["ttl_days"] = body.ttl_days
            row, created = trust.sign_release(db, img, **kwargs)
    except trust.TrustConflict as e:
        raise HTTPException(status.HTTP_409_CONFLICT, e.reason)
    except trust.TrustError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, e.reason)
    return ReleaseSignatureOut(
        image_id=row.image_id, model=row.model, version=row.version,
        counter=row.counter, expires=row.expires, keyid=row.keyid,
        duplicate=not created, envelope=json.loads(row.envelope),
    )


@router.post("/releases/publish", response_model=ReleaseSignatureOut)
def publish_signed(body: PublishSignedIn, db: Session = Depends(get_session)) -> ReleaseSignatureOut:
    """Store metadata produced by an offline/air-gapped signing workstation."""
    img = db.get(Image, body.image_id)
    if img is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "image_not_found")
    try:
        row, created = trust.publish_envelope(
            db, img, body.envelope, idempotency_key=body.idempotency_key
        )
    except trust.TrustConflict as e:
        raise HTTPException(status.HTTP_409_CONFLICT, e.reason)
    except trust.TrustError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, e.reason)
    return ReleaseSignatureOut(
        image_id=row.image_id, model=row.model, version=row.version,
        counter=row.counter, expires=row.expires, keyid=row.keyid,
        duplicate=not created, envelope=json.loads(row.envelope),
    )


@router.get("/releases", response_model=list[ReleaseSignatureOut])
def list_releases(model: str | None = None, db: Session = Depends(get_session)):
    q = select(ReleaseSignature).order_by(ReleaseSignature.model, ReleaseSignature.counter)
    if model:
        q = q.where(ReleaseSignature.model == model)
    return [
        ReleaseSignatureOut(
            image_id=r.image_id, model=r.model, version=r.version,
            counter=r.counter, expires=r.expires, keyid=r.keyid,
            envelope=json.loads(r.envelope),
        )
        for r in db.scalars(q).all()
    ]


@router.get("/rejections", response_model=list[FailureReceiptOut])
def admin_list_rejections(
    device_id: str | None = None,
    reason: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_session),
):
    q = select(FailureReceipt).order_by(FailureReceipt.created_at.desc()).limit(min(limit, 1000))
    if device_id:
        q = q.where(FailureReceipt.device_id == device_id)
    if reason:
        q = q.where(FailureReceipt.reason == reason)
    return db.scalars(q).all()


@router.get("/overview")
def overview(db: Session = Depends(get_session)):
    return {
        "devices": int(db.scalar(select(func.count(Device.id))) or 0),
        "images": int(db.scalar(select(func.count(Image.id))) or 0),
        "campaigns": int(db.scalar(select(func.count(Campaign.id))) or 0),
        "batches": int(db.scalar(select(func.count(Batch.id))) or 0),
        "assignments": int(db.scalar(select(func.count(Assignment.id))) or 0),
        "server_time": utcnow(),
    }
