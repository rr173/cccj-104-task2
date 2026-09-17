"""Standalone runner used by test_trust_restart.py.

Runs in its own OS process so two invocations prove trust state survives a
real process restart (fresh interpreter, fresh SQLAlchemy engine, same on-disk
DB + artifact store + keyring). Driven by FOTA_RESTART_PHASE.
"""
from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

HEADERS = {"X-Device-Id": "d1"}


def _blob(pat, n=200):
    return (pat * n)[:n]


def phase1():
    from app.main import app

    with TestClient(app) as c:
        blob = _blob(b"RESTART-FW")
        r = c.post(
            "/api/admin/images",
            data={"model": "m", "version": "2.0.0",
                  "min_bootloader": "1.0.0", "max_bootloader": "9.0.0"},
            files={"file": ("f.bin", io.BytesIO(blob), "application/octet-stream")},
        )
        r.raise_for_status()
        img = r.json()
        camp = c.post("/api/admin/campaigns",
                      json={"name": "c", "image_id": img["id"]}).json()
        b = c.post("/api/admin/batches",
                   json={"campaign_id": camp["id"], "hardware_batch": "H",
                         "stage": 1, "quota_mode": "absolute",
                         "quota_value": 5}).json()
        c.post(f"/api/admin/batches/{b['id']}/action", json={"action": "activate"})
        c.post("/api/admin/devices",
               json={"id": "d1", "model": "m", "hardware_batch": "H",
                     "bootloader": "1.2", "current_version": "1.9"})
        ci = c.post("/api/device/check-in", headers=HEADERS).json()
        assert ci["offered"]
        offer = ci["offer"]
        for ch in offer["chunks"]:
            rr = c.get(
                f"/api/device/artifacts/{img['id']}/chunks/{ch['index']}",
                params={"assignment_id": offer["assignment_id"]}, headers=HEADERS)
            rr.raise_for_status()
        asg = offer["assignment_id"]
        for etype, key, payload in [
            ("downloading", "restart-downloading", {"resumed": False}),
            ("downloaded", "restart-downloaded", {}),
            ("installing", "restart-installing", {}),
            ("installed", "restart-installed", {"version": "2.0.0", "slot": "B"}),
        ]:
            rr = c.post("/api/device/events", headers=HEADERS,
                        json={"assignment_id": asg, "event_type": etype,
                              "idempotency_key": key, "payload": payload})
            rr.raise_for_status()

        from app.db import SessionLocal
        from app.models import DeviceTrustState
        sdb = SessionLocal()
        counter = sdb.get(DeviceTrustState, "d1").highest_counter
        sdb.close()
        print(json.dumps({"ok": True, "highest_counter": counter,
                          "counter": ci["offer"]["security_counter"]}))


def phase2():
    from app.main import app
    from tests.trust_helpers import release_envelope, signer_key

    with TestClient(app) as c:
        rels = c.get("/api/admin/releases").json()
        root = c.get("/api/admin/trust/m/status").json()

        blob2 = _blob(b"OLDFW")
        r = c.post(
            "/api/admin/images",
            data={"model": "m", "version": "1.9.5",
                  "min_bootloader": "1.0.0", "max_bootloader": "9.0.0",
                  "sign": "false"},
            files={"file": ("o.bin", io.BytesIO(blob2), "application/octet-stream")},
        )
        r.raise_for_status()
        img2 = r.json()
        env = release_envelope(
            model="m", sha256=img2["sha256"], version="1.9.5",
            counter=0, signer=signer_key("m"),
        )
        rp = c.post("/api/admin/releases/publish",
                    json={"image_id": img2["id"], "envelope": env,
                          "idempotency_key": "post-restart-low-key"})
        assert rp.status_code == 200, rp.text
        camp2 = c.post("/api/admin/campaigns",
                       json={"name": "c2", "image_id": img2["id"]}).json()
        b2 = c.post("/api/admin/batches",
                    json={"campaign_id": camp2["id"], "hardware_batch": "H",
                          "stage": 1, "quota_mode": "absolute",
                          "quota_value": 5}).json()
        c.post(f"/api/admin/batches/{b2['id']}/action", json={"action": "activate"})

        ci = c.post("/api/device/check-in", headers=HEADERS).json()
        assert ci["offered"]
        asg2 = ci["offer"]["assignment_id"]
        for etype, key in [("downloading", "r2-downloading-key"), ("downloaded", "r2-downloaded-key")]:
            rr = c.post("/api/device/events", headers=HEADERS,
                        json={"assignment_id": asg2, "event_type": etype,
                              "idempotency_key": key, "payload": {}})
            assert rr.status_code == 200, (etype, rr.text)
        rr = c.post("/api/device/events", headers=HEADERS,
                    json={"assignment_id": asg2, "event_type": "installing",
                          "idempotency_key": "r2-installing-key", "payload": {}})
        gate_status = rr.status_code
        gate_reason = rr.json().get("detail", {}).get("reason")
        recs = c.get("/api/device/rejections", headers=HEADERS).json()
        print(json.dumps({
            "rels": len(rels),
            "root_version": root["version"],
            "gate_status": gate_status,
            "gate_reason": gate_reason,
            "has_rollback_receipt": any(x["reason"] == "counter_rollback" for x in recs),
        }))


if __name__ == "__main__":
    {"1": phase1, "2": phase2}[os.environ["FOTA_RESTART_PHASE"]]()
