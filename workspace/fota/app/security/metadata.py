"""Signed metadata documents and their verification rules.

Two document types, each wrapped in a detached-signature envelope::

    {"signed": <document>, "signatures": [{"keyid": ..., "sig": <b64url>}]}

``root`` documents
    Versioned per device *model*. They pin the set of authorized root keys and
    the delegated release signers (each active or revoked). v1 is the trust
    anchor provisioned out of band; every later version N must be signed by
    BOTH the retiring root (a key declared in vN-1) AND the incoming root (a
    key declared in vN). A device coming back online after a long outage may
    consume a continuous v2, v3, v4 chain in one wake-up; a gap, a revoked
    signer, an expired document or a backwards version all fail closed.

``release`` documents
    One per published firmware release. They bind the artifact digest to the
    device model, human/display version, a monotonically increasing security
    counter and an expiry. They may be signed by any active delegated signer
    or by a currently-declared root key; after a cutover a retired root's key
    is neither, so old-root-signed content is rejected.
"""
from __future__ import annotations

import dataclasses
import hashlib
from datetime import datetime
from typing import Any, Iterable

from .canonical import canonical_bytes, normalize_scalar
from .keys import SigningKey, b64d, b64e, verify

ROOT_DOCUMENT_TYPE = "root"
RELEASE_DOCUMENT_TYPE = "release"

SIGNER_ACTIVE = "active"
SIGNER_REVOKED = "revoked"


class TrustError(Exception):
    """Verification failed. ``reason`` is a stable machine-readable code that
    is surfaced verbatim in durable failure receipts (queryable / idempotent
    retries), so do not make it user prose."""

    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason if detail is None else f"{reason}:{detail}")
        self.reason = reason


def key_id(public_b64: str) -> str:
    return b64e(hashlib.sha256(b64d(public_b64)).digest())


def _parse_dt(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise TrustError("bad_metadata", f"{field}_not_iso8601")
    try:
        text = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise TrustError("bad_metadata", f"{field}_not_iso8601") from None
    if dt.tzinfo is None:
        raise TrustError("bad_metadata", f"{field}_needs_timezone")
    return dt


def _digest_ok(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 7 + 64
        and all(c in "0123456789abcdef" for c in value[7:])
    )


# --------------------------------------------------------------------------- #
# Root documents
# --------------------------------------------------------------------------- #
@dataclasses.dataclass(frozen=True)
class RootView:
    """Verified, normalized view of one root version."""

    version: int
    model: str
    expires: datetime
    root_keys: dict[str, str]          # keyid -> public b64
    signers: dict[str, dict[str, str]]  # keyid -> {"public", "state"}

    def active_signer_ids(self) -> frozenset[str]:
        return frozenset(k for k, v in self.signers.items() if v["state"] == SIGNER_ACTIVE)


def normalize_root(doc: dict, *, now: datetime | None = None) -> RootView:
    if not isinstance(doc, dict) or doc.get("_type") != ROOT_DOCUMENT_TYPE:
        raise TrustError("bad_metadata", "root_type")
    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise TrustError("bad_metadata", "root_version")
    model = doc.get("model")
    if not isinstance(model, str) or not model:
        raise TrustError("bad_metadata", "root_model")
    expires = _parse_dt(doc.get("expires"), "expires")
    if now is not None and expires <= now:
        raise TrustError("root_expired", f"v{version}")

    rk = doc.get("root_keys")
    if not isinstance(rk, list) or not rk:
        raise TrustError("bad_metadata", "root_keys_empty")
    root_keys: dict[str, str] = {}
    for entry in rk:
        if not isinstance(entry, dict) or "public" not in entry:
            raise TrustError("bad_metadata", "root_key_entry")
        pub = entry["public"]
        try:
            kid = entry.get("id") or key_id(pub)
        except Exception:
            raise TrustError("bad_metadata", "root_key_public") from None
        if kid in root_keys:
            raise TrustError("bad_metadata", "duplicate_root_keyid")
        if key_id(pub) != kid:
            raise TrustError("bad_metadata", "root_key_id_mismatch")
        root_keys[kid] = pub

    sm = doc.get("signers", {})
    if not isinstance(sm, dict):
        raise TrustError("bad_metadata", "signers_map")
    signers: dict[str, dict] = {}
    for kid, entry in sm.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("public"), str):
            raise TrustError("bad_metadata", f"signer_{kid}")
        state = entry.get("state")
        if state not in (SIGNER_ACTIVE, SIGNER_REVOKED):
            raise TrustError("bad_metadata", f"signer_state_{kid}")
        if key_id(entry["public"]) != kid:
            raise TrustError("bad_metadata", f"signer_id_mismatch_{kid}")
        signers[kid] = {"public": entry["public"], "state": state}

    return RootView(version, model, expires, root_keys, signers)


def _envelope_signed_bytes(envelope: Any) -> tuple[dict, list[dict], bytes]:
    if not isinstance(envelope, dict) or not isinstance(envelope.get("signed"), dict):
        raise TrustError("bad_metadata", "envelope")
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise TrustError("bad_metadata", "signatures_empty")
    clean: list[dict] = []
    for s in sigs:
        if not isinstance(s, dict) or not isinstance(s.get("keyid"), str) or not isinstance(s.get("sig"), str):
            raise TrustError("bad_metadata", "signature_entry")
        clean.append({"keyid": s["keyid"], "sig": s["sig"]})
    return envelope["signed"], clean, canonical_bytes(envelope["signed"])


def _sig_verifies(sig: dict, keyids_to_public: dict[str, str], blob: bytes) -> bool:
    pub = keyids_to_public.get(sig["keyid"])
    if pub is None:
        return False
    return verify(pub, sig["sig"], blob)


def verify_root_envelope(
    envelope: Any,
    *,
    trusted: RootView | None,
    model: str,
    now: datetime,
) -> RootView:
    """Verify one root envelope against the currently trusted root view.

    ``trusted=None`` verifies a genesis (v1) root: it must be self-consistent
    and self-signed by one of its own root keys. Authenticity of the v1 anchor
    itself is established out of band (factory provisioning / admin endpoint).
    """
    doc, sigs, blob = _envelope_signed_bytes(envelope)
    view = normalize_root(doc, now=now)
    if view.model != model:
        raise TrustError("root_model_mismatch")

    if trusted is None:
        if view.version != 1:
            raise TrustError("bad_root_chain", "genesis_must_be_v1")
        if not any(_sig_verifies(s, view.root_keys, blob) for s in sigs):
            raise TrustError("root_signature_invalid", "genesis_self_signature")
        return view

    if view.version != trusted.version + 1:
        if view.version <= trusted.version:
            raise TrustError("root_version_rollback", f"{view.version}<={trusted.version}")
        raise TrustError("root_chain_gap", f"{trusted.version}->{view.version}")
    if view.model != trusted.model:
        raise TrustError("root_model_mismatch")

    # DUAL AUTHORIZATION: the retiring root signs off AND the incoming root
    # proves possession of its newly declared key.
    old_ok = any(_sig_verifies(s, trusted.root_keys, blob) for s in sigs)
    new_ok = any(_sig_verifies(s, view.root_keys, blob) for s in sigs)
    if not old_ok:
        raise TrustError("root_signature_invalid", "missing_old_root_authorization")
    if not new_ok:
        raise TrustError("root_signature_invalid", "missing_new_root_authorization")

    # Signer delegation changes must be monotonic: a public key pinned to an id
    # can never silently change, and a revoked signer can never be reanimated
    # (that would let a compromise vote itself back in).
    for kid, entry in view.signers.items():
        old = trusted.signers.get(kid)
        if old is not None:
            if old["public"] != entry["public"]:
                raise TrustError("signer_key_changed", kid)
            if old["state"] == SIGNER_REVOKED and entry["state"] == SIGNER_ACTIVE:
                raise TrustError("revoked_signer_reactivated", kid)
    return view


# --------------------------------------------------------------------------- #
# Release documents
# --------------------------------------------------------------------------- #
@dataclasses.dataclass(frozen=True)
class ReleaseClaims:
    model: str
    artifact_digest: str
    version: str
    counter: int
    expires: datetime


def verify_release_envelope(
    envelope: Any,
    *,
    root: RootView,
    now: datetime,
) -> ReleaseClaims:
    doc, sigs, blob = _envelope_signed_bytes(envelope)
    if doc.get("_type") != RELEASE_DOCUMENT_TYPE:
        raise TrustError("bad_metadata", "release_type")
    model = doc.get("model")
    if model != root.model:
        raise TrustError("release_model_mismatch")
    digest = doc.get("artifact_digest")
    if not _digest_ok(digest):
        raise TrustError("bad_metadata", "artifact_digest")
    version = doc.get("version")
    if not isinstance(version, str) or not version:
        raise TrustError("bad_metadata", "version")
    counter = doc.get("counter")
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise TrustError("bad_metadata", "counter")
    expires = _parse_dt(doc.get("expires"), "expires")
    if expires <= now:
        raise TrustError("release_expired")

    # Authorized signers: active delegated signers plus currently-declared root
    # keys. A retired root key is intentionally absent after cutover.
    accepted: dict[str, str] = {
        kid: entry["public"] for kid, entry in root.signers.items()
        if entry["state"] == SIGNER_ACTIVE
    }
    for kid, pub in root.root_keys.items():
        accepted.setdefault(kid, pub)

    if not any(_sig_verifies(s, accepted, blob) for s in sigs):
        # Classify the policy reason precisely so the durable receipt can say
        # *why* a release was refused (revoked vs unknown vs just-bad-sig).
        sig_ids = [s["keyid"] for s in sigs]
        revoked = [
            kid for kid in sig_ids
            if kid in root.signers and root.signers[kid]["state"] == SIGNER_REVOKED
        ]
        if revoked and not (set(sig_ids) & accepted.keys()):
            raise TrustError("revoked_signer")
        if set(sig_ids) - (set(root.signers) | set(root.root_keys)):
            raise TrustError("untrusted_signer")
        raise TrustError("release_signature_invalid")

    return ReleaseClaims(model, digest, version, counter, expires)


# --------------------------------------------------------------------------- #
# Builders (publisher / offline signing tool side)
# --------------------------------------------------------------------------- #
def _sign_doc(doc: dict, signers: Iterable[tuple[str, SigningKey]]) -> dict:
    blob = canonical_bytes(doc)
    return {
        "signed": doc,
        "signatures": [
            {"keyid": kid, "sig": key.sign(blob)}
            for kid, key in signers
        ],
    }


def build_root_document(
    *,
    version: int,
    model: str,
    expires: datetime,
    root_keys: list[SigningKey | str],
    signers: dict[str, SigningKey | str] | None = None,
    signer_states: dict[str, str] | None = None,
) -> dict:
    """Assemble an unsigned root document. Keys may be :class:`SigningKey`
    objects (id/public derived) or bare public-key strings."""
    rk = []
    for k in root_keys:
        pub = k.public_b64 if isinstance(k, SigningKey) else k
        rk.append({"id": key_id(pub), "public": pub})
    sm = {}
    for kid, k in (signers or {}).items():
        pub = k.public_b64 if isinstance(k, SigningKey) else k
        sm[key_id(pub)] = {
            "public": pub,
            "state": (signer_states or {}).get(kid, SIGNER_ACTIVE),
        }
    return {
        "_type": ROOT_DOCUMENT_TYPE,
        "spec_version": "1.0",
        "version": version,
        "model": model,
        "expires": normalize_scalar(expires),
        "root_keys": rk,
        "signers": sm,
    }


def build_root_envelope(
    *,
    version: int,
    model: str,
    expires: datetime,
    root_keys: list[SigningKey | str],
    signers: dict[str, SigningKey | str] | None = None,
    signer_states: dict[str, str] | None = None,
    authorizing_keys: list[SigningKey],
) -> dict:
    """Build and sign a root envelope.

    For a rotation ``authorizing_keys`` must contain BOTH a key declared in the
    previous root and a key declared in the new document; for genesis it must
    contain the genesis root key itself.
    """
    doc = build_root_document(
        version=version,
        model=model,
        expires=expires,
        root_keys=root_keys,
        signers=signers,
        signer_states=signer_states,
    )
    pairs = [(key_id(key.public_b64), key) for key in authorizing_keys]
    return _sign_doc(doc, pairs)


def build_release_document(
    *,
    model: str,
    artifact_digest: str,
    version: str,
    counter: int,
    expires: datetime,
) -> dict:
    if not _digest_ok(artifact_digest):
        raise TrustError("bad_metadata", "artifact_digest")
    return {
        "_type": RELEASE_DOCUMENT_TYPE,
        "spec_version": "1.0",
        "model": model,
        "artifact_digest": artifact_digest,
        "version": str(version),
        "counter": int(counter),
        "expires": normalize_scalar(expires),
    }


def build_release_envelope(
    *,
    model: str,
    artifact_digest: str,
    version: str,
    counter: int,
    expires: datetime,
    signer: SigningKey,
) -> dict:
    doc = build_release_document(
        model=model,
        artifact_digest=artifact_digest,
        version=version,
        counter=counter,
        expires=expires,
    )
    return _sign_doc(doc, [(key_id(signer.public_b64), signer)])
