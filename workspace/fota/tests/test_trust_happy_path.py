"""Acceptance: a release under the initial root downloads and installs;
the offer carries deterministically serialized signed metadata."""
from __future__ import annotations

import json

from .conftest import h
from .trust_helpers import setup_campaign


def test_initial_root_release_downloads_and_installs(client, admin, make_device):
    s = setup_campaign(client, admin)
    d = make_device("d1")
    d.register()

    body = d.check_in()
    assert body["offered"] is True
    # First contact delivers the v1 trust anchor.
    assert body["root_version"] == 1
    assert len(body["root_updates"]) == 1
    env = body["root_updates"][0]
    assert env["signed"]["version"] == 1
    assert env["signed"]["model"] == "term-x1"

    offer = body["offer"]
    rel = offer["signed_release"]
    signed = rel["signed"]
    # Signed metadata covers every required claim.
    assert signed["_type"] == "release"
    assert signed["model"] == "term-x1"
    assert signed["version"] == "2.0.0"
    assert signed["artifact_digest"] == "sha256:" + s["img"]["sha256"]
    assert isinstance(signed["counter"], int) and signed["counter"] >= 1
    assert "expires" in signed
    assert rel["signatures"] and rel["signatures"][0]["sig"]

    # Deterministic serialization: re-serializing the signed body is byte
    # stable (that is what the signature was made over).
    from app.security.canonical import canonical_bytes

    assert canonical_bytes(signed) == canonical_bytes(json.loads(json.dumps(signed)))

    out = d.download()
    assert out["aborted"] is None
    res = d.install()
    assert res["result"] == "installed"
    # Anti-rollback watermark + accepted root are durable on the device.
    assert d.trust.highest_counter == signed["counter"]
    assert d.trust.root_version == 1
    assert d.active_slot == "B"
    assert client.get("/api/admin/devices").json()[0]["current_version"] == "2.0.0"


def test_trust_state_survives_client_restart(client, admin, make_device, tmp_path):
    setup_campaign(client, admin)
    d = make_device("d1")
    d.register()
    d.check_in()
    d.download()
    d.install()
    ctr = d.trust.highest_counter

    # Power loss / new process: rebuild the terminal from its workdir.
    d2 = make_device("d1")
    d2.register()
    assert d2.trust.highest_counter == ctr
    assert d2.trust.root_version == 1
    assert d2.active_slot == "B"
    assert d2.facts["current_version"] == "2.0.0"


def test_no_repeated_anchor_after_it_is_applied(client, admin, make_device):
    setup_campaign(client, admin)
    d = make_device("d1")
    d.register()
    first = d.check_in()
    assert len(first["root_updates"]) == 1
    # A second check-in must not resend v1 (which would look like rollback).
    second = d.check_in()
    assert second["root_updates"] == []
    assert d.trust.root_version == 1
