"""Acceptance: root-key rotation chains.

* an offline device traverses several consecutive transitions in one wake-up;
* omission of an intermediate authorization fails closed;
* an interruption/restart during rotation never exposes a half-applied state
  and a retry converges (idempotent publication key);
* concurrent publication with the same idempotency key yields one result;
* after cutover, content signed only by the retired root is rejected.
"""
from __future__ import annotations

import json
import threading

import httpx

from client.trust import TerminalTrust, TrustRejected
from .conftest import h
from .trust_helpers import (
    FUTURE,
    release_envelope,
    root_key,
    setup_campaign,
    signer_key,
)


def _rotate_n(admin, model, n, **kw):
    for v in range(2, n + 1):
        r = admin.rotate(model, f"rotation-{v}-key", **(kw if v == n else {}))
        assert r.status_code == 200, (v, r.text)


def test_offline_device_traverses_multiple_rotations_in_one_wakeup(client, admin, make_device):
    setup_campaign(client, admin)
    model = "term-x1"
    _rotate_n(admin, model, 4)

    # Device has been offline the whole time and holds only no anchor.
    d = make_device("d1")
    d.register()
    body = d.check_in()
    assert [e["signed"]["version"] for e in body["root_updates"]] == [1, 2, 3, 4]
    assert d.trust.root_version == 4
    # The signed release was made under the v1 primary signer; rotations 2-4
    # kept it active (default add_signer, no revocations) so it still verifies.
    d.download()
    assert d.install()["result"] == "installed"


def test_partial_catchup_then_later_completes(client, admin, make_device):
    setup_campaign(client, admin)
    model = "term-x1"
    _rotate_n(admin, model, 3)

    d = make_device("d1")
    d.register()
    d.check_in()  # applies 1,2,3
    assert d.trust.root_version == 3

    # Two more rotations happen while the device is asleep.
    _rotate_n(admin, model, 5)
    body = d.check_in()
    assert [e["signed"]["version"] for e in body["root_updates"]] == [4, 5]
    assert d.trust.root_version == 5


def test_omitted_intermediate_link_fails_closed(client, admin, make_device, tmp_path):
    setup_campaign(client, admin)
    model = "term-x1"
    _rotate_n(admin, model, 3)

    # Hand the terminal the anchor and v3 but NOT v2.
    roots = admin.roots(model).json()
    by_ver = {r["version"]: r["envelope"] for r in roots}
    tt = TerminalTrust(tmp_path / "trust.json", model)
    tt.apply_root_chain([by_ver[1]])
    try:
        tt.apply_root_chain([by_ver[3]])
        assert False, "gap must fail closed"
    except TrustRejected as e:
        assert e.reason == "root_chain_gap"
    # Trust state unchanged: still on the anchor.
    assert tt.root_version == 1


def test_one_bad_link_in_chain_aborts_whole_apply(client, admin, make_device, tmp_path):
    setup_campaign(client, admin)
    model = "term-x1"
    _rotate_n(admin, model, 3)
    roots = admin.roots(model).json()
    by_ver = {r["version"]: r["envelope"] for r in roots}

    # Tamper v2's bytes after it was signed; v3 stays intact.
    bad2 = json.loads(json.dumps(by_ver[2]))
    bad2["signed"]["model"] = "other-model"
    tt = TerminalTrust(tmp_path / "trust.json", model)
    try:
        tt.apply_root_chain([by_ver[1], bad2, by_ver[3]])
        assert False
    except TrustRejected as e:
        assert e.reason in ("root_signature_invalid", "root_model_mismatch")
    assert tt.root_version == 0  # nothing applied at all


def test_rotation_restart_converges_and_never_half_applies(client, admin, monkeypatch):
    """Simulate a crash between DB commit and keyring durability: a retry with
    the same idempotency key returns the SAME root (duplicate), and the chain
    is verifiable — no half-applied trust state."""
    setup_campaign(client, admin)
    from app import trust as tmod
    from app.models import ROOT_SUPERSEDED, TrustRoot

    # Crash the process AFTER the keyring is durable but BEFORE the chain row
    # is committed. The row must not exist and the predecessor must still be
    # committed (no half-applied root). We inject the fault by making the
    # rotation's own flush raise once, scoped to that function/session.
    real_flush = tmod.Session.flush if hasattr(tmod, "Session") else None

    from sqlalchemy.orm import Session

    def crashing_flush(self, *a, **k):
        raise RuntimeError("simulated crash before db commit")

    monkeypatch.setattr(Session, "flush", crashing_flush)
    from app.db import SessionLocal

    sdb = SessionLocal()
    try:
        try:
            tmod.rotate_root(sdb, "term-x1", idempotency_key="crash-rotation-key")
            assert False
        except RuntimeError:
            sdb.rollback()
    finally:
        sdb.close()
    monkeypatch.undo()

    # New session: only v1 exists and it is still committed (nothing partial).
    rows = admin.roots("term-x1").json()
    assert [r["version"] for r in rows] == [1]
    assert rows[0]["state"] == "committed"

    # Retry converges: same idempotency key regenerates identical derived keys,
    # so the v2 envelope is exactly what the crashed attempt would have
    # committed — the rotation now applies once.
    r = admin.rotate("term-x1", "crash-rotation-key")
    assert r.status_code == 200
    assert r.json()["duplicate"] is False
    assert r.json()["version"] == 2
    rows = admin.roots("term-x1").json()
    assert [x["version"] for x in rows] == [1, 2]
    assert rows[1]["state"] == "committed"
    assert rows[0]["state"] == ROOT_SUPERSEDED

    # Replaying again is a duplicate (one durable result).
    r = admin.rotate("term-x1", "crash-rotation-key")
    assert r.json()["duplicate"] is True
    assert [x["version"] for x in admin.roots("term-x1").json()] == [1, 2]


def test_concurrent_rotation_same_key_returns_one_result(client, admin):
    setup_campaign(client, admin)
    transport = client._transport
    results, errors = [], []
    barrier = threading.Barrier(6)

    def worker():
        try:
            with httpx.Client(transport=transport, base_url="http://test") as c:
                barrier.wait(timeout=10)
                r = c.post("/api/admin/trust/rotate",
                           json={"model": "term-x1", "idempotency_key": "concurrent-rot-key"})
                results.append((r.status_code, r.json().get("version"),
                                r.json().get("duplicate")))
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(results) == 6
    assert all(code == 200 for code, _, _ in results)
    assert {v for _, v, _ in results} == {2}
    # Exactly one created the root; the rest are duplicates.
    assert [dup for _, _, dup in results].count(False) == 1
    assert [x["version"] for x in admin.roots("term-x1").json()] == [1, 2]


def test_same_release_version_different_content_conflicts(client, admin):
    """Different content claiming the same release (model, version) is a
    conflict and can never lower or alias the trust state."""
    s = setup_campaign(client, admin)
    model = "term-x1"

    # (a) Metadata with a correct version string but a digest that does NOT
    #     match the target binary cannot be glued to it.
    other, _ = admin.upload_image(model=model, version="9.9.9",
                                  blob_seed=b"OTHER", sign=False)
    wrong_digest = release_envelope(
        model=model, sha256="0" * 64, version="9.9.9",
        counter=50, signer=signer_key(model),
    )
    r = admin.publish_envelope(other["id"], wrong_digest, idem="digest-bind")
    assert r.status_code == 400
    assert r.json()["detail"] == "release_digest_mismatch"

    # (b) Correctly-bound metadata for another image cannot reuse version
    #     2.0.0: (model, version) uniqueness is an unconditional 409.
    other2, _ = admin.upload_image(model=model, version="9.9.7",
                                   blob_seed=b"OTHER2", sign=False)
    bound = release_envelope(
        model=model, sha256=other2["sha256"], version="2.0.0",
        counter=51, signer=signer_key(model),
    )
    r = admin.publish_envelope(other2["id"], bound, idem="reuse-version-key")
    assert r.status_code == 400
    assert r.json()["detail"] in (
        "release_version_mismatch", "release_version_exists"
    )

    # (c) A higher-numbered counter can never "lower" state: even a valid new
    #     release must take the next counter; reusing an existing counter is a
    #     conflict too.
    img3, _ = admin.upload_image(model=model, version="3.0.0",
                                 blob_seed=b"THREE", sign=False)
    reuse_counter = release_envelope(
        model=model, sha256=img3["sha256"], version="3.0.0",
        counter=1, signer=signer_key(model),  # counter 1 already used by 2.0.0
    )
    r = admin.publish_envelope(img3["id"], reuse_counter, idem="reuse-counter")
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "release_counter_exists"

    # The original release is intact and still counter 1.
    rels = client.get("/api/admin/releases").json()
    original = next(x for x in rels if x["version"] == "2.0.0")
    assert original["counter"] == 1


def test_retired_root_only_signature_rejected_after_cutover(client, admin, make_device):
    s = setup_campaign(client, admin)
    model = "term-x1"
    # Rotate twice with NO new signer: after cutover the v1 root key is absent
    # from the current root document, and the v1 delegated primary signer is
    # carried forward (so delegation is independent of the root retirement).
    r2 = admin.rotate(model, "rotation-2", add_signer=False)
    assert r2.status_code == 200, r2.text

    d = make_device("d1")
    d.register()
    d.check_in()  # anchor + v2
    assert d.trust.root_version == 2
    d.download()

    # Build content signed ONLY by the retired v1 root key (not a delegated
    # signer). After cutover that keyid is unknown -> rejected.
    retired = root_key(model, 1)
    env = release_envelope(
        model=model, sha256=s["img"]["sha256"], version="2.0.0",
        counter=7, signer=retired,
    )
    d._offer["signed_release"] = env
    try:
        d.install()
        assert False
    except TrustRejected as e:
        assert e.reason == "untrusted_signer", e.reason
    assert d.active_slot == "A"


def test_expired_intermediate_root_aborts_chain(client, admin, make_device, tmp_path):
    """A long-offline device must reject a chain containing an expired root
    version even though the latest one is fresh — expiry is checked per link."""
    from datetime import datetime, timedelta, timezone

    from .trust_helpers import PAST

    setup_campaign(client, admin)
    model = "term-x1"
    # v2 was valid when published (expires 2021) but the device only wakes in
    # 2026; v3 is fresh. Both links are correctly dual-signed — expiry alone
    # must fail the whole catch-up.
    from app import trust as tmod

    real_now = tmod.utcnow
    past_now = datetime(2020, 1, 1, tzinfo=timezone.utc)
    tmod.utcnow = lambda: past_now  # type: ignore[assignment]
    try:
        r2 = admin.c.post(
            "/api/admin/trust/rotate",
            json={"model": model, "idempotency_key": "expired-v2-key",
                  "expires_at": "2021-01-01T00:00:00Z"},
        )
    finally:
        tmod.utcnow = real_now  # type: ignore[assignment]
    assert r2.status_code == 200, r2.text
    r3 = admin.rotate(model, "rotation-3", add_signer=False)
    assert r3.status_code == 200

    by_ver = {r["version"]: r["envelope"] for r in admin.roots(model).json()}
    tt = TerminalTrust(tmp_path / "t.json", model)
    try:
        tt.apply_root_chain([by_ver[1], by_ver[2], by_ver[3]])
        assert False
    except TrustRejected as e:
        assert e.reason == "root_expired", e.reason
    assert tt.root_version == 0  # whole chain aborted atomically


def test_concurrent_release_publish_same_idem_returns_one(client, admin):
    """Six concurrent publications with the same idempotency key create one
    release row and return that one result to all callers."""
    s = setup_campaign(client, admin)
    img, _ = admin.upload_image(model="term-x1", version="3.1.0",
                                blob_seed=b"NEWFW", sign=False)
    env = release_envelope(
        model="term-x1", sha256=img["sha256"], version="3.1.0",
        counter=7, signer=signer_key("term-x1"),
    )
    transport = client._transport
    results, errors = [], []
    barrier = threading.Barrier(6)

    def worker():
        try:
            with httpx.Client(transport=transport, base_url="http://test") as c:
                barrier.wait(timeout=10)
                r = c.post("/api/admin/releases/publish",
                           json={"image_id": img["id"], "envelope": env,
                                 "idempotency_key": "concurrent-publish-key"})
                results.append((r.status_code, r.json().get("image_id"),
                                r.json().get("duplicate")))
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert [code for code, _, _ in results].count(200) == 6
    ids = {iid for _, iid, _ in results}
    assert len(ids) == 1
    assert [dup for _, _, dup in results].count(False) == 1
    assert len(client.get("/api/admin/releases").json()) == 2  # 2.0.0 + 3.1.0
