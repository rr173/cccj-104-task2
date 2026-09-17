"""Acceptance: expired signatures, revoked signers and security-counter
rollback are all rejected before the critical write."""
from __future__ import annotations

import copy

from client.trust import TerminalTrust, TrustRejected
from .conftest import h
from .trust_helpers import (
    FUTURE,
    PAST,
    release_envelope,
    root_key,
    setup_campaign,
    signer_key,
)


def test_expired_release_metadata_is_rejected(client, admin, make_device):
    s = setup_campaign(client, admin)
    # Re-publish metadata with the same valid signer but a past expiry. The
    # (model, version) row already exists, so publish via a second image is not
    # possible; instead drive the device-side gate with an expired envelope.
    d = make_device("d1")
    d.register(); d.check_in(); d.download()

    expired = release_envelope(
        model="term-x1",
        sha256=s["img"]["sha256"],
        version="2.0.0",
        counter=5,
        signer=signer_key("term-x1"),
        expires=PAST,
    )
    d._offer["signed_release"] = expired
    try:
        d.install()
        assert False
    except TrustRejected as e:
        assert e.reason == "release_expired"
    assert d.active_slot == "A"
    recs = client.get("/api/device/rejections", headers=h("d1")).json()
    assert recs[0]["reason"] == "release_expired"


def test_counter_rollback_rejected_on_device(client, admin, make_device):
    s = setup_campaign(client, admin)
    d = make_device("d1")
    d.register(); d.check_in(); d.download(); d.install()
    accepted = d.trust.highest_counter
    assert accepted == 1

    # Attacker replays validly-signed metadata with a lower counter. The
    # signature checks out, but the device's durable watermark rejects it.
    low = release_envelope(
        model="term-x1",
        sha256=s["img"]["sha256"],
        version="2.0.0",
        counter=0,
        signer=signer_key("term-x1"),
    )
    try:
        d.trust.verify_release(low, artifact_sha256=s["img"]["sha256"], version="2.0.0")
        assert False
    except TrustRejected as e:
        assert e.reason == "counter_rollback"


def test_counter_rollback_rejected_by_server_gate(client, admin, make_device):
    s = setup_campaign(client, admin)
    # Device d1 installs counter 1 and records the watermark server-side.
    d1 = make_device("d1")
    d1.register(); d1.check_in(); d1.download(); d1.install()

    # Attacker now serves an older 1.9.5 build (different version so it is
    # offerable) with a valid delegated signature but counter 0. Uploaded
    # unsigned so the (model, version) row is free for this hostile metadata.
    img2, _ = admin.upload_image(model="term-x1", version="1.9.5",
                                 blob_seed=b"FW-OLD", sign=False)
    low_env = release_envelope(
        model="term-x1", sha256=img2["sha256"], version="1.9.5",
        counter=0, signer=signer_key("term-x1"),
    )
    r = admin.publish_envelope(img2["id"], low_env, idem="low-counter-idem")
    assert r.status_code == 200, r.text

    camp2 = admin.campaign(img2["id"])
    b2 = admin.batch(camp2["id"], quota_value=10)
    admin.action(b2["id"], "activate")

    # A tampered client that ignores its local gate still cannot reach the
    # critical region: drive the FSM straight to the downloaded->installing
    # boundary over raw HTTP. The SERVER's authoritative gate refuses.
    body = d1.check_in()
    assert body["offered"] is True
    assert body["offer"]["image_id"] == img2["id"]
    asg_id = body["offer"]["assignment_id"]

    def ev(etype, key, payload=None):
        return client.post(
            "/api/device/events", headers=h("d1"),
            json={"assignment_id": asg_id, "event_type": etype,
                  "idempotency_key": key, "payload": payload or {}},
        )

    assert ev("downloading", "raw-downloading-key") .status_code == 200
    assert ev("downloaded", "raw-downloaded-key").status_code == 200
    r = ev("installing", "raw-installing-key", {"artifact_sha256": img2["sha256"]})
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["reason"] == "counter_rollback"

    # The active slot is untouched and the assignment never entered installing.
    asg = next(a for a in client.get("/api/admin/assignments").json()
               if a["id"] == asg_id)
    assert asg["install_state"] == "downloaded"
    recs = client.get("/api/device/rejections", headers=h("d1")).json()
    assert any(x["reason"] == "counter_rollback" for x in recs)


def test_revoked_signer_is_rejected(client, admin, make_device):
    s = setup_campaign(client, admin)
    model = "term-x1"
    # Rotate to v2 adding a new signer s2; then rotate to v3 revoking the
    # PRIMARY signer. v3 is dual-authorized by the v2 + v3 root keys.
    primary = _primary_id(admin, model)
    r2 = admin.rotate(model, "rotation-2")
    assert r2.status_code == 200, r2.text
    # v3 revokes the ORIGINAL primary signer and brings no new signer, so the
    # signer set after cutover is {primary revoked, s2 active}.
    r3 = admin.rotate(model, "rotation-3", revoke_signer_ids=[primary], add_signer=False)
    assert r3.status_code == 200, r3.text
    signers3 = r3.json()["signers"]
    assert signers3[primary] == "revoked"
    assert any(st == "active" for st in signers3.values())

    # The revoked keyid can never be reactivated by a later, otherwise-valid
    # dual-authorized rotation.
    from app.security import (
        TrustError,
        build_root_envelope,
        normalize_root,
        verify_root_envelope,
    )
    from datetime import datetime, timezone

    v3_view = normalize_root(r3.json()["envelope"]["signed"])
    r3key = root_key(model, 3)
    carried: dict[str, str] = {
        f"c{n}": entry["public"] for n, entry in enumerate(v3_view.signers.values())
    }
    # Flip every (revoked) signer back to active — the attack.
    reactivated_states = {alias: "active" for alias in carried}
    env4 = build_root_envelope(
        version=4, model=model, expires=FUTURE,
        root_keys=[r3key], signers=carried, signer_states=reactivated_states,
        authorizing_keys=[r3key, r3key],
    )
    try:
        verify_root_envelope(env4, trusted=v3_view, model=model,
                             now=datetime.now(timezone.utc))
        assert False
    except TrustError as e:
        assert e.reason == "revoked_signer_reactivated", e.reason

    d = make_device("d1")
    d.register()
    body = d.check_in()
    # One wake-up traverses both rotations consecutively.
    assert body["root_version"] == 3
    assert [e["signed"]["version"] for e in body["root_updates"]] == [1, 2, 3]
    assert d.trust.root_version == 3

    # The offered 2.0.0 metadata is signed by the primary delegated signer,
    # which v3 revoked. The device refuses at the end-of-download trust gate,
    # before any flash write.
    try:
        d.download()
        assert False
    except TrustRejected as e:
        assert e.reason == "revoked_signer"
    assert d.active_slot == "A"
    asg = client.get("/api/admin/assignments").json()[0]
    assert asg["install_state"] in ("downloading", "assigned")
    recs = client.get("/api/device/rejections", headers=h("d1")).json()
    assert any(x["reason"] == "revoked_signer" for x in recs)


def _primary_id(admin, model):
    st = admin.trust_status(model).json()
    # primary is the only delegated signer at v1
    return list(st["signers"].keys())[0]


def test_counter_watermark_is_durable_across_restart(client, admin, make_device):
    setup_campaign(client, admin)
    d = make_device("d1")
    d.register(); d.check_in(); d.download(); d.install()
    # Rebuild trust store as a new process would.
    fresh = TerminalTrust(d.workdir / "trust.json", "term-x1")
    assert fresh.highest_counter == 1
    low = release_envelope(
        model="term-x1", sha256="0" * 64, version="1.0.0", counter=1,
        signer=signer_key("term-x1"),
    )
    try:
        fresh.verify_release(low)
        assert False
    except TrustRejected as e:
        assert e.reason == "counter_rollback"
