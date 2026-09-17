"""Server-side trust authority.

Owns four things:

1. A small on-disk offline-signing *keyring* (root + delegated signer seeds).
   In production these live on an air-gapped machine/HSM; here they are JSON
   under ``KEYS_ROOT`` purely so the reference service is runnable end to end.
   The service verifies with :mod:`app.security` exactly like a terminal, so it
   can never accept a document a device would reject.
2. Genesis (v1) root for each model: one root key + one active delegated
   release signer.
3. Root rotation: every new version is dual-authorized (old root + new root),
   verified against the running chain, then committed together with the
   supersession of its predecessor in ONE transaction. A crash at any point
   leaves either the old committed root or the new one — never a half state.
   Rotations are deterministic in their idempotency key: retrying with the same
   key regenerates the same new keys and envelope and converges.
4. Release signing: deterministic signed metadata with a per-model
   monotonically increasing security counter; counters and (model, version)
   are unique so trust state can never be lowered or aliased by different
   content claiming the same version.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import config
from .models import (
    ROOT_COMMITTED,
    ROOT_SUPERSEDED,
    DeviceTrustState,
    FailureReceipt,
    Image,
    ReleaseSignature,
    TrustRoot,
    utcnow,
)
from .security import (
    SIGNER_ACTIVE,
    SIGNER_REVOKED,
    SigningKey,
    TrustError,
    build_release_envelope,
    build_root_envelope,
    key_id,
    normalize_root,
    verify_release_envelope,
    verify_root_envelope,
)
from .security.keys import from_seed_bytes

_trust_lock = threading.RLock()

DEFAULT_RELEASE_TTL_DAYS = 3650
DEFAULT_ROOT_TTL_DAYS = 3650
PRIMARY_SIGNER_ALIAS = "primary"


class TrustConflict(Exception):
    """409-class publishing conflict (same version/counter, other content)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Keyring (offline signing material)
# --------------------------------------------------------------------------- #
def _keyring_path() -> Path:
    return config.KEYS_ROOT / "keyring.json"


def _load_keyring() -> dict:
    p = _keyring_path()
    if p.exists():
        return json.loads(p.read_text())
    return {"roots": {}, "signers": {}}


def _save_keyring(data: dict) -> None:
    config.KEYS_ROOT.mkdir(parents=True, exist_ok=True)
    p = _keyring_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(p)  # atomic publish: a crash never tears the keyring


def _entry(key: SigningKey) -> dict:
    return {"seed": key.seed_b64, "public": key.public_b64, "id": key_id(key.public_b64)}


def _model_bucket(kr: dict, kind: str, model: str) -> dict:
    return kr.setdefault(kind, {}).setdefault(model, {})


def _put(kr: dict, kind: str, model: str, alias: str, key: SigningKey) -> None:
    _model_bucket(kr, kind, model)[alias] = _entry(key)


def _get(kr: dict, kind: str, model: str, alias: str) -> SigningKey:
    try:
        return SigningKey.from_seed(kr[kind][model][alias]["seed"])
    except KeyError:
        raise TrustError("unknown_signing_key", f"{kind}/{model}/{alias}") from None


# --------------------------------------------------------------------------- #
# Root chain reads
# --------------------------------------------------------------------------- #
def latest_committed_root(db: Session, model: str) -> TrustRoot | None:
    # Every applied version stays on the chain (a device returning after a
    # long outage needs the full v1..N history); the "current" root is simply
    # the highest version. ROOT_SUPERSEDED marks predecessors for auditing,
    # never removes them.
    return db.scalars(
        select(TrustRoot)
        .where(TrustRoot.model == model)
        .order_by(TrustRoot.version.desc())
        .limit(1)
    ).first()


def root_envelopes(db: Session, model: str, *, after_version: int = 0) -> list[dict]:
    """All chain envelopes strictly above ``after_version``, ascending.

    Includes superseded versions: a device that has only the v1 anchor must be
    able to walk v2, v3, v4 in one wake-up. A hole in versions still fails
    closed on the device even if the server were willing to skip one."""
    rows = db.scalars(
        select(TrustRoot)
        .where(TrustRoot.model == model, TrustRoot.version > after_version)
        .order_by(TrustRoot.version.asc())
    ).all()
    return [json.loads(r.envelope) for r in rows]


def _root_view(row: TrustRoot, *, now: datetime | None = None):
    envelope = json.loads(row.envelope)
    return normalize_root(
        envelope["signed"] if "signed" in envelope else envelope, now=now
    )


def genesis_status(db: Session, model: str) -> dict | None:
    row = latest_committed_root(db, model)
    if row is None:
        return None
    view = _root_view(row)
    return {
        "model": model,
        "version": row.version,
        "root_key_ids": sorted(view.root_keys),
        "signers": {k: v["state"] for k, v in view.signers.items()},
        "expires": view.expires,
    }


# --------------------------------------------------------------------------- #
# Genesis
# --------------------------------------------------------------------------- #
def ensure_genesis(
    db: Session,
    model: str,
    *,
    expires: datetime | None = None,
    idempotency_key: str | None = None,
) -> tuple[TrustRoot, bool]:
    """Return (v1 row, created?). Idempotent: an existing genesis is returned
    untouched — a second genesis attempt can never reset trust."""
    with _trust_lock:
        existing = latest_committed_root(db, model)
        if existing is not None:
            return existing, False

        now = utcnow()
        expires = expires or (now + timedelta(days=DEFAULT_ROOT_TTL_DAYS))
        kr = _load_keyring()
        roots = _model_bucket(kr, "roots", model)
        signers = _model_bucket(kr, "signers", model)
        root_key = roots.get("v1")
        if root_key is None:
            rk = SigningKey.generate()
            _put(kr, "roots", model, "v1", rk)
            root_key = _entry(rk)
        rk = SigningKey.from_seed(root_key["seed"])
        sk = signers.get(PRIMARY_SIGNER_ALIAS)
        if sk is None:
            skey = SigningKey.generate()
            _put(kr, "signers", model, PRIMARY_SIGNER_ALIAS, skey)
            sk = _entry(skey)
        skey = SigningKey.from_seed(sk["seed"])
        _save_keyring(kr)

        envelope = build_root_envelope(
            version=1,
            model=model,
            expires=expires,
            root_keys=[rk],
            signers={PRIMARY_SIGNER_ALIAS: skey},
            authorizing_keys=[rk],
        )
        # A terminal verifies the same property before trusting v1.
        verify_root_envelope(envelope, trusted=None, model=model, now=now)

        row = TrustRoot(
            model=model,
            version=1,
            envelope=json.dumps(envelope),
            state=ROOT_COMMITTED,
            idempotency_key=idempotency_key,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            # Raced another genesis (multi-worker): the winner is authoritative.
            db.rollback()
            got = latest_committed_root(db, model)
            assert got is not None
            return got, False
        db.refresh(row)
        return row, True


# --------------------------------------------------------------------------- #
# Rotation
# --------------------------------------------------------------------------- #
def rotate_root(
    db: Session,
    model: str,
    *,
    expires: datetime | None = None,
    revoke_signer_ids: list[str] | None = None,
    add_signer: bool = True,
    idempotency_key: str,
) -> tuple[TrustRoot, bool]:
    """Dual-authorized root rotation, committed atomically.

    Returns ``(row, created)``; ``created=False`` is the idempotent replay of
    the same (model, idempotency_key) request.
    """
    revoke_signer_ids = list(revoke_signer_ids or [])
    with _trust_lock:
        replay = db.scalar(
            select(TrustRoot).where(
                TrustRoot.model == model,
                TrustRoot.idempotency_key == idempotency_key,
            )
        )
        if replay is not None:
            return replay, False

        old_row = latest_committed_root(db, model)
        if old_row is None:
            raise TrustError("no_genesis", model)
        now = utcnow()
        old_view = normalize_root(json.loads(old_row.envelope)["signed"])
        new_version = old_view.version + 1
        expires = expires or (now + timedelta(days=DEFAULT_ROOT_TTL_DAYS))

        kr = _load_keyring()
        old_root_key = _get(kr, "roots", model, f"v{old_view.version}")

        # Deterministic incoming material: a retried rotation converges.
        new_root_seed = hashlib.sha256(
            f"root|{model}|{new_version}|{idempotency_key}".encode()
        ).digest()
        new_root_key = from_seed_bytes(new_root_seed)
        _put(kr, "roots", model, f"v{new_version}", new_root_key)

        # Carried-forward signers only need their pinned public key + state
        # (they live in the signed document); brand-new signers bring real
        # signing material. Revoked signers are preserved as revoked forever:
        # the verifier forbids reactivating a revoked keyid.
        signer_material: dict[str, SigningKey | str] = {}
        signer_states: dict[str, str] = {}
        for n, (kid, entry) in enumerate(old_view.signers.items()):
            alias = f"carried-{n}"
            signer_material[alias] = entry["public"]
            signer_states[alias] = (
                SIGNER_REVOKED if kid in set(revoke_signer_ids) else entry["state"]
            )
        if add_signer:
            alias = f"s{new_version}"
            sseed = hashlib.sha256(
                f"signer|{model}|{new_version}|{idempotency_key}".encode()
            ).digest()
            skey = from_seed_bytes(sseed)
            _put(kr, "signers", model, alias, skey)
            signer_material[alias] = skey
            signer_states[alias] = SIGNER_ACTIVE

        envelope = build_root_envelope(
            version=new_version,
            model=model,
            expires=expires,
            root_keys=[new_root_key],
            signers=signer_material,
            signer_states=signer_states,
            authorizing_keys=[old_root_key, new_root_key],
        )
        # Device-equivalent verification BEFORE persisting anything.
        verify_root_envelope(envelope, trusted=old_view, model=model, now=now)

        # Write the signing material durably BEFORE committing the chain row
        # (write-ahead): a later rotation must always be able to load this
        # version's root key to dual-authorize the next one. An orphaned key
        # from a crash before commit is harmless (a retry with the same
        # idempotency key regenerates identical derived material and converges).
        _save_keyring(kr)

        # Atomic state swap: insert-new + supersede-old in one transaction.
        new_row = TrustRoot(
            model=model,
            version=new_version,
            envelope=json.dumps(envelope),
            state=ROOT_COMMITTED,
            idempotency_key=idempotency_key,
        )
        old_row.state = ROOT_SUPERSEDED
        db.add(new_row)
        try:
            db.flush()
            db.commit()
        except IntegrityError:
            db.rollback()
            got = db.scalar(
                select(TrustRoot).where(
                    TrustRoot.model == model,
                    TrustRoot.idempotency_key == idempotency_key,
                )
            )
            if got is not None:
                return got, False
            raise
        db.refresh(new_row)
        return new_row, True


# --------------------------------------------------------------------------- #
# Release signing / publication
# --------------------------------------------------------------------------- #
def _max_counter(db: Session, model: str) -> int:
    return int(db.scalar(
        select(func.coalesce(func.max(ReleaseSignature.counter), 0))
        .where(ReleaseSignature.model == model)
    ) or 0)


def sign_release(
    db: Session,
    image: Image,
    *,
    signer_alias: str = PRIMARY_SIGNER_ALIAS,
    counter: int | None = None,
    expires: datetime | None = None,
    ttl_days: int = DEFAULT_RELEASE_TTL_DAYS,
    idempotency_key: str | None = None,
) -> tuple[ReleaseSignature, bool]:
    """Sign an image with a keyring signer and publish the signed metadata."""
    with _trust_lock:
        root_row = latest_committed_root(db, image.model)
        if root_row is None:
            raise TrustError("no_genesis", image.model)
        now = utcnow()
        root_view = normalize_root(json.loads(root_row.envelope)["signed"])

        kr = _load_keyring()
        signer = _get(kr, "signers", image.model, signer_alias)
        kid = key_id(signer.public_b64)
        is_root_key = False
        if kid not in root_view.signers and kid in root_view.root_keys:
            is_root_key = True
        if not is_root_key and root_view.signers.get(kid, {}).get("state") != SIGNER_ACTIVE:
            raise TrustError("signer_not_authorized", signer_alias)

        if counter is None:
            counter = _max_counter(db, image.model) + 1
        expires = expires or (now + timedelta(days=ttl_days))
        envelope = build_release_envelope(
            model=image.model,
            artifact_digest="sha256:" + image.sha256,
            version=image.version,
            counter=counter,
            expires=expires,
            signer=signer,
        )
        verify_release_envelope(envelope, root=root_view, now=now)
        return _publish_envelope(db, image, envelope, idempotency_key=idempotency_key)


def sign_release_with_root_key(
    db: Session,
    image: Image,
    *,
    root_version: int,
    counter: int | None = None,
    expires: datetime | None = None,
    idempotency_key: str | None = None,
) -> tuple[ReleaseSignature, bool]:
    """Sign with a root key (root keys may publish releases while current).

    Used to prove post-cutover rejection: after rotation the retired root key
    is absent from the new root document, so such metadata fails verification.
    """
    with _trust_lock:
        kr = _load_keyring()
        signer = _get(kr, "roots", image.model, f"v{root_version}")
        if counter is None:
            counter = _max_counter(db, image.model) + 1
        expires = expires or (utcnow() + timedelta(days=DEFAULT_RELEASE_TTL_DAYS))
        envelope = build_release_envelope(
            model=image.model,
            artifact_digest="sha256:" + image.sha256,
            version=image.version,
            counter=counter,
            expires=expires,
            signer=signer,
        )
        return _publish_envelope(db, image, envelope, idempotency_key=idempotency_key)


def publish_envelope(
    db: Session,
    image: Image,
    envelope: dict,
    *,
    idempotency_key: str | None = None,
) -> tuple[ReleaseSignature, bool]:
    """Publish externally (offline) signed metadata.

    Structural/binding checks only — the metadata is not required to verify
    against today's root here: offline signing stages artifacts ahead of
    cutover and historical artifacts remain stored. Devices (and the
    installing gate) do the actual trust evaluation.
    """
    return _publish_envelope(db, image, envelope, idempotency_key=idempotency_key)


def _publish_envelope(
    db: Session,
    image: Image,
    envelope: dict,
    *,
    idempotency_key: str | None,
) -> tuple[ReleaseSignature, bool]:
    with _trust_lock:
        if idempotency_key is not None:
            prior = db.scalar(
                select(ReleaseSignature).where(
                    ReleaseSignature.model == image.model,
                    ReleaseSignature.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                return prior, False

        signed = envelope.get("signed") if isinstance(envelope, dict) else None
        if not isinstance(signed, dict):
            raise TrustError("bad_metadata", "envelope")
        if signed.get("model") != image.model:
            raise TrustError("release_model_mismatch")
        if str(signed.get("version")) != str(image.version):
            raise TrustError("release_version_mismatch")
        if signed.get("artifact_digest") != "sha256:" + image.sha256:
            raise TrustError("release_digest_mismatch")
        ctr = signed.get("counter")
        if not isinstance(ctr, int) or isinstance(ctr, bool) or ctr < 0:
            raise TrustError("bad_metadata", "counter")

        # Deterministic conflict detection (the DB constraints remain the
        # durable race backstop, but their error text is dialect-specific).
        if db.scalar(
            select(ReleaseSignature.image_id).where(
                ReleaseSignature.model == image.model,
                ReleaseSignature.version == str(image.version),
            )
        ):
            raise TrustConflict("release_version_exists")
        if db.scalar(
            select(ReleaseSignature.image_id).where(
                ReleaseSignature.model == image.model,
                ReleaseSignature.counter == ctr,
            )
        ):
            raise TrustConflict("release_counter_exists")

        kid = None
        sigs = envelope.get("signatures") or []
        if sigs and isinstance(sigs[0], dict):
            kid = sigs[0].get("keyid")

        from .security.metadata import _parse_dt  # local: keeps surface small

        row = ReleaseSignature(
            image_id=image.id,
            model=image.model,
            version=str(image.version),
            counter=ctr,
            expires=_parse_dt(signed.get("expires"), "expires"),
            keyid=kid or "",
            envelope=json.dumps(envelope),
            idempotency_key=idempotency_key,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            if idempotency_key is not None:
                prior = db.scalar(
                    select(ReleaseSignature).where(
                        ReleaseSignature.model == image.model,
                        ReleaseSignature.idempotency_key == idempotency_key,
                    )
                )
                if prior is not None:
                    return prior, False
            # Re-derive the conflict after a concurrent insert won the race.
            if db.scalar(
                select(ReleaseSignature.image_id).where(
                    ReleaseSignature.model == image.model,
                    ReleaseSignature.version == str(image.version),
                )
            ):
                raise TrustConflict("release_version_exists") from None
            raise TrustConflict("release_counter_exists") from None
        db.refresh(row)
        return row, True


def release_for(db: Session, image_id: str) -> ReleaseSignature | None:
    return db.get(ReleaseSignature, image_id)


# --------------------------------------------------------------------------- #
# Device-side verification (server enforces the same gate at the critical phase)
# --------------------------------------------------------------------------- #
def get_device_trust(db: Session, device_id: str, model: str) -> DeviceTrustState:
    row = db.get(DeviceTrustState, device_id)
    if row is None:
        # root_version 0 == unprovisioned: the first check-in returns the v1
        # anchor as the first "root update".
        row = DeviceTrustState(
            device_id=device_id, model=model, root_version=0, highest_counter=0
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def evaluate_release_for_device(
    db: Session,
    *,
    device_id: str,
    model: str,
    envelope: dict,
    now: datetime | None = None,
) -> tuple:
    """Full trust evaluation a device performs before its critical write.

    Walks the committed root chain from the device's recorded version (which
    catches expired roots / revoked signers in intermediate versions only to
    the extent the *current* root embeds them — each transition itself was
    verified when applied), validates signatures/expiry and enforces the
    persisted anti-rollback counter. Raises TrustError on any failure.
    """
    now = now or utcnow()
    state = get_device_trust(db, device_id, model)
    root_row = latest_committed_root(db, model)
    if root_row is None:
        raise TrustError("no_trust_anchor", model)
    root_view = normalize_root(json.loads(root_row.envelope)["signed"], now=now)
    claims = verify_release_envelope(envelope, root=root_view, now=now)
    if claims.counter <= state.highest_counter:
        raise TrustError(
            "counter_rollback", f"{claims.counter}<={state.highest_counter}"
        )
    return claims, root_view, state


def bump_device_trust(
    db: Session, *, device_id: str, model: str, root_version: int, counter: int
) -> None:
    """Persist the accepted watermark. Only moves forward (defense in depth at
    the DB layer too)."""
    state = get_device_trust(db, device_id, model)
    state.root_version = max(state.root_version, root_version)
    state.highest_counter = max(state.highest_counter, counter)
    db.add(state)


# --------------------------------------------------------------------------- #
# Durable failure receipts
# --------------------------------------------------------------------------- #
def record_rejection(
    db: Session,
    *,
    device_id: str,
    reason: str,
    idempotency_key: str,
    assignment_id: str | None = None,
    model: str | None = None,
    image_id: str | None = None,
    image_sha256: str | None = None,
    version: str | None = None,
    counter_seen: int | None = None,
    root_version_seen: int | None = None,
    stage: str = "pre_flash",
    detail: str | None = None,
) -> tuple[FailureReceipt, bool]:
    """Idempotent durable rejection record. A retry with the same stable key
    returns the original row with ``created=False`` and has no side effects."""
    with _trust_lock:
        prior = db.scalar(
            select(FailureReceipt).where(
                FailureReceipt.device_id == device_id,
                FailureReceipt.idempotency_key == idempotency_key,
            )
        )
        if prior is not None:
            return prior, False
        row = FailureReceipt(
            id=str(uuid.uuid4()),
            device_id=device_id,
            assignment_id=assignment_id,
            model=model,
            image_id=image_id,
            image_sha256=image_sha256,
            version=version,
            counter_seen=counter_seen,
            root_version_seen=root_version_seen,
            reason=reason[:64],
            stage=stage[:32],
            detail=(detail or None) and str(detail)[:2000],
            idempotency_key=idempotency_key,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            got = db.scalar(
                select(FailureReceipt).where(
                    FailureReceipt.device_id == device_id,
                    FailureReceipt.idempotency_key == idempotency_key,
                )
            )
            assert got is not None
            return got, False
        db.refresh(row)
        return row, True
