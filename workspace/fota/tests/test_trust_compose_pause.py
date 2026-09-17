"""Acceptance: the signed-trust guarantees compose with the pre-existing
pause gate and critical-region safe wind-down — no regression."""
from __future__ import annotations

from client.trust import TrustRejected
from .trust_helpers import setup_campaign


def test_pause_before_download_blocks_and_signing_still_verifies(client, admin, make_device):
    s = setup_campaign(client, admin, quota=5)
    d = make_device("d1")
    d.register()
    d.check_in()
    admin.action(s["batch"]["id"], "pause")

    # Existing pause semantics unchanged.
    body = d.check_in()
    assert body["offered"] is False
    assert body["reason"] == "batch_paused"
    # Root view is still served while paused (independent of rollout gate).
    assert body["root_version"] == 1


def test_pause_after_verified_download_then_resume_installs(client, admin, make_device):
    s = setup_campaign(client, admin, quota=5, size=200)
    d = make_device("d1")
    d.register()
    d.check_in()
    d.download()  # trust gate passed; now "downloaded"
    admin.action(s["batch"]["id"], "pause")

    # Pause must block entering the critical region (existing behavior).
    r = client.post(
        "/api/device/events", headers=_h(d),
        json={"assignment_id": d._offer["assignment_id"], "event_type": "installing",
              "idempotency_key": "installing-while-paused-key", "payload": {}},
    )
    assert r.status_code == 409

    # Resume: signed metadata still verifies and install completes.
    admin.action(s["batch"]["id"], "resume", force=True)
    d.check_in()
    assert d.install()["result"] == "installed"
    assert d.trust.highest_counter == 1


def test_critical_region_wind_down_survives_rotation_cutover(client, admin, make_device):
    """A device already flashing must finish safely even if the operator
    rotates roots mid-flash; its installed receipt is accepted and only then
    does the new root govern the NEXT release."""
    s = setup_campaign(client, admin, quota=5)
    d = make_device("d1")
    d.register()
    d.check_in()
    d.download()
    claims = d._verify_offer_before_flash(s["img"]["sha256"])
    # Enter the critical region (flash writes started).
    d._event("installing", {"slot": "B"})

    # Operator rotates the root while the device is mid-flash.
    r = admin.rotate("term-x1", "rotation-midflash-key", add_signer=False)
    assert r.status_code == 200

    # Safe wind-down: the critical-region device still gets its manifest and
    # may confirm the install of the release it already validated under v1.
    body = d.check_in()
    assert body["offered"] is True
    assert body["offer"]["finalize_only"] is True
    r = client.post(
        "/api/device/events", headers=_h(d),
        json={"assignment_id": d._offer["assignment_id"], "event_type": "installed",
              "idempotency_key": "installed-midflash-key",
              "payload": {"version": "2.0.0", "slot": "B"}},
    )
    assert r.status_code == 200
    assert client.get("/api/admin/devices").json()[0]["current_version"] == "2.0.0"


def test_rejected_release_does_not_block_later_valid_install(client, admin, make_device):
    """A durable rejection (bad metadata) is terminal for that attempt but a
    subsequent valid signed release installs normally — receipts are
    idempotent, not a sticky ban."""
    import copy

    from client.trust import TrustRejected

    s = setup_campaign(client, admin)
    d = make_device("d1")
    d.register(); d.check_in(); d.download()

    tampered = copy.deepcopy(d._offer["signed_release"])
    tampered["signed"]["counter"] += 9
    d._offer["signed_release"] = tampered
    try:
        d.install()
    except TrustRejected:
        pass
    assert len(client.get("/api/device/rejections", headers=_h(d)).json()) == 1

    # Re-check-in restores the authoritative (valid) offer; install succeeds.
    d.check_in()
    assert d.install()["result"] == "installed"
    assert d.active_slot == "B"


def _h(d):
    return {"X-Device-Id": d.device_id}
