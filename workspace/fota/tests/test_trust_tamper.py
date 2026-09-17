"""Acceptance: modified metadata or any modified block is rejected BEFORE
critical writes, the active boot slot remains bootable, and a durable,
queryable, idempotently-retryable failure receipt is produced."""
from __future__ import annotations

import copy

from client.trust import TrustRejected
from .conftest import h
from .trust_helpers import setup_campaign


def _downloaded_device(d):
    d.register()
    d.check_in()
    d.download()  # full verified blob + trust gate passed; not yet installing


def _receipts(client, dev):
    return client.get("/api/device/rejections", headers=h(dev)).json()


def test_tampered_metadata_is_rejected_before_flash(client, admin, make_device):
    setup_campaign(client, admin)
    d = make_device("d1")
    _downloaded_device(d)
    good = copy.deepcopy(d._offer["signed_release"])

    tampered = copy.deepcopy(good)
    tampered["signed"]["counter"] = good["signed"]["counter"] + 10
    d._offer["signed_release"] = tampered

    # install() re-verifies at the critical boundary.
    try:
        d.install()
        assert False, "expected rejection"
    except TrustRejected as e:
        assert e.reason == "release_signature_invalid"

    # Active slot untouched.
    assert d.active_slot == "A"
    assert d.slots["A"] == "1.9.0"
    # Assignment never entered the critical region.
    asg = client.get("/api/admin/assignments").json()[0]
    assert asg["install_state"] == "downloaded"

    # Durable, queryable receipt.
    recs = _receipts(client, "d1")
    assert len(recs) == 1
    assert recs[0]["reason"] == "release_signature_invalid"
    assert recs[0]["stage"] == "pre_flash"
    assert recs[0]["counter_seen"] == good["signed"]["counter"] + 10


def test_tampered_metadata_digest_field_is_rejected(client, admin, make_device):
    setup_campaign(client, admin)
    d = make_device("d1")
    _downloaded_device(d)
    good = copy.deepcopy(d._offer["signed_release"])

    # Mutating the signed digest invalidates the signature outright.
    tampered = copy.deepcopy(good)
    tampered["signed"]["artifact_digest"] = "sha256:" + "0" * 64
    d._offer["signed_release"] = tampered
    try:
        d.install()
        assert False
    except TrustRejected as e:
        assert e.reason == "release_signature_invalid"
    assert d.active_slot == "A"


def test_modified_block_is_rejected_and_old_slot_bootable(client, admin, make_device):
    s = setup_campaign(client, admin)
    d = make_device("d1")
    d.register()
    d.check_in()
    # Download fully, then corrupt a byte of the local blob (storage tamper /
    # bit rot). The whole-image sha256 check fires before the trust gate.
    d.download()
    path = d.workdir / f"{s['img']['sha256']}.bin"
    raw = bytearray(path.read_bytes())
    raw[5] ^= 0xFF
    path.write_bytes(bytes(raw))

    # A subsequent download() re-verifies blocks (refetch heals), but a direct
    # critical-boundary verification over the corrupt blob must fail closed:
    import hashlib

    bad = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        d._verify_offer_before_flash(bad)
        assert False
    except TrustRejected as e:
        assert e.reason == "artifact_digest_mismatch"
    assert d.active_slot == "A"

    # The device heals by re-fetching the corrupt block and installs normally.
    d.download()
    assert d.install()["result"] == "installed"


def test_rejection_receipt_retry_is_idempotent(client, admin, make_device):
    setup_campaign(client, admin)
    d = make_device("d1")
    _downloaded_device(d)
    tampered = copy.deepcopy(d._offer["signed_release"])
    tampered["signed"]["counter"] += 5
    d._offer["signed_release"] = tampered

    first_id = None
    for _ in range(3):
        try:
            d.install()
        except TrustRejected:
            pass
    recs = _receipts(client, "d1")
    assert len(recs) == 1, recs
    # Server also records its own gate receipt only if the device reaches the
    # installing transition; here the client refused first, so exactly one.


def test_rejection_post_is_idempotent_with_same_key(client, admin, make_device):
    setup_campaign(client, admin)
    d = make_device("d1")
    d.register(); d.check_in(); d.download()
    body = {
        "assignment_id": d._offer["assignment_id"],
        "reason": "release_expired",
        "stage": "pre_flash",
        "idempotency_key": "stable-receipt-key-0001",
        "image_id": d._offer["image_id"],
        "image_sha256": d._offer["image_sha256"],
        "model": "term-x1",
        "version": "2.0.0",
        "counter_seen": 1,
    }
    r1 = client.post("/api/device/rejections", headers=h("d1"), json=body)
    r2 = client.post("/api/device/rejections", headers=h("d1"), json=body)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["id"] == r2.json()["id"]
    recs = _receipts(client, "d1")
    assert len(recs) == 1
    # Queryable through the admin view too.
    admin_recs = client.get("/api/admin/rejections?reason=release_expired").json()
    assert len(admin_recs) == 1
    assert admin_recs[0]["reason"] == "release_expired"
