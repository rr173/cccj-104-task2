"""Minimal FOTA client that runs ON the terminal.

It models the parts the problem statement cares about:
* register + periodic check-in, safe to repeat at any time
* block downloads with per-block sha256 verification; on reconnect it only
  re-fetches blocks it does not already hold verbatim (resume from verified)
* A/B slot install: on failure the new slot is marked bad, the device boots the
  previous slot and posts `failed` + `rollback_complete` with the reason
* every POST carries a stable idempotency key; retried receipts are harmless
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import httpx


class SimDevice:
    def __init__(
        self,
        base_url: str,
        *,
        device_id: str,
        model: str,
        hardware_batch: str,
        bootloader: str,
        current_version: str,
        workdir: Path,
        fail_install: bool = False,
        timeout: float = 10.0,
    ):
        self.client = httpx.Client(base_url=base_url, timeout=timeout)
        self.device_id = device_id
        self.facts = {
            "id": device_id,
            "model": model,
            "hardware_batch": hardware_batch,
            "bootloader": bootloader,
            "current_version": current_version,
        }
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.fail_install = fail_install
        self.slots = {"A": current_version, "B": None}
        self.active_slot = "A"
        self._offer: dict | None = None
        self._idem = self._load_idem()
        self._load_persisted_state()  # survive process restart / power loss

    # ----- state persistence across process restarts -----
    @property
    def _state_path(self) -> Path:
        return self.workdir / "state.json"

    def _load_persisted_state(self) -> None:
        if self._state_path.exists():
            st = json.loads(self._state_path.read_text())
            self.slots = st["slots"]
            self.active_slot = st["active_slot"]
            self.facts["current_version"] = st["current_version"]

    def _save_state(self) -> None:
        self._state_path.write_text(
            json.dumps(
                {
                    "slots": self.slots,
                    "active_slot": self.active_slot,
                    "current_version": self.facts["current_version"],
                }
            )
        )

    # ----- persistence / idempotency keys -----
    @property
    def _idem_path(self) -> Path:
        return self.workdir / "idem.json"

    def _load_idem(self) -> dict[str, str]:
        if self._idem_path.exists():
            return json.loads(self._idem_path.read_text())
        return {}

    def _idem_key(self, key_name: str) -> str:
        """Stable key per named milestone; a fresh name => fresh key."""
        v = self._idem.get(key_name)
        if not v:
            v = hashlib.sha256(
                f"{self.device_id}:{key_name}:{time.time_ns()}".encode()
            ).hexdigest()[:32]
            self._idem[key_name] = v
            self._idem_path.write_text(json.dumps(self._idem))
        return v

    def _event(self, event_type: str, payload: dict | None = None, *, key: str | None = None):
        if not self._offer:
            raise RuntimeError("no offer")

        def post(key_name: str):
            return self.client.post(
                "/api/device/events",
                headers=self._h(),
                json={
                    "assignment_id": self._offer["assignment_id"],
                    "event_type": event_type,
                    "idempotency_key": self._idem_key(key_name),
                    "payload": payload or {},
                },
            )

        r = post(key or event_type)
        if r.status_code == 409 and "illegal_transition" in r.text:
            # Local FSM view is stale (crash between server commit and local
            # persistence). Resync once and retry with a fresh milestone key.
            self.check_in()
            r = post(f"{key or event_type}:resync:{time.time_ns()}")
        r.raise_for_status()
        out = r.json()
        if out.get("to_state"):
            self._offer["install_state"] = out["to_state"]
        return out

    def close(self):
        self.client.close()

    # ----- API helpers -----
    def _h(self) -> dict:
        return {"X-Device-Id": self.device_id}

    def register(self):
        r = self.client.post("/api/device/register", json=self.facts)
        r.raise_for_status()
        return r.json()

    def check_in(self):
        r = self.client.post("/api/device/check-in", headers=self._h())
        r.raise_for_status()
        body = r.json()
        if body.get("offer"):
            self._offer = body["offer"]
        return body

    # ----- block download with verified resume -----
    def _blob_path(self) -> Path:
        return self.workdir / f"{self._offer['image_sha256']}.bin"

    def _verified_blocks(self, manifest) -> dict[int, bytes]:
        path = self._blob_path()
        if not path.exists():
            return {}
        data = path.read_bytes()
        good: dict[int, bytes] = {}
        cs = manifest["chunk_size"]
        for ch in manifest["chunks"]:
            i, size = ch["index"], ch["size"]
            block = data[i * cs:i * cs + size]
            if len(block) == size and hashlib.sha256(block).hexdigest() == ch["sha256"]:
                good[i] = block
        return good

    def _persist(self, manifest, good: dict[int, bytes]):
        buf = bytearray(manifest["size"])
        cs = manifest["chunk_size"]
        for i, block in good.items():
            buf[i * cs:i * cs + len(block)] = block
        self._blob_path().write_bytes(bytes(buf))

    def download(self, *, fail_after_chunks: int | None = None):
        """Fetch every block not locally verified. `fail_after_chunks` simulates
        an intermittent link; calling download() again resumes from verified."""
        assert self._offer, "check_in first"
        manifest = self._offer

        good = self._verified_blocks(manifest)

        # Telemetry: safe to fire repeatedly (idempotent), even after a crash
        # before the FSM transition landed.
        self._event("download_started", {"resumed": bool(good)}, key="download_started")
        if self._offer["install_state"] == "assigned":
            # First bytes move / resume after crash before the transition:
            # the stable key makes assigned -> downloading exactly-once.
            self._event("downloading", {"resumed": bool(good)}, key="downloading")

        new_fetched = 0
        for ch in manifest["chunks"]:
            i = ch["index"]
            if i in good:
                continue
            if fail_after_chunks is not None and new_fetched >= fail_after_chunks:
                self._persist(manifest, good)
                raise ConnectionError(
                    f"simulated disconnect after {new_fetched} new chunk(s)"
                )
            r = self.client.get(
                f"/api/device/artifacts/{manifest['image_id']}/chunks/{i}",
                params={"assignment_id": manifest["assignment_id"]},
                headers=self._h(),
            )
            if r.status_code == 409:
                self._persist(manifest, good)
                return {"aborted": r.json().get("detail", "paused"), "verified_blocks": len(good)}
            r.raise_for_status()
            if hashlib.sha256(r.content).hexdigest() != ch["sha256"]:
                raise IOError(f"chunk {i} hash mismatch")
            good[i] = r.content
            new_fetched += 1
            if self._offer["install_state"] == "assigned":
                # First verified byte advances the FSM; stable key means a crash
                # between HTTP receipt and local bookkeeping stays replay-safe.
                self._event("downloading", {"resumed": bool(good) and i > 0}, key="downloading")
            self._persist(manifest, good)

        blob = b"".join(good[i] for i in sorted(good))
        if hashlib.sha256(blob).hexdigest() != manifest["image_sha256"]:
            raise IOError("full image sha256 mismatch")

        if self._offer["install_state"] != "downloaded":
            self._event("downloaded", {"size": len(blob)})
        return {"aborted": None, "verified_blocks": len(good), "new_blocks": new_fetched}

    # ----- install / rollback -----
    def install(self) -> dict:
        assert self._offer and self._offer["install_state"] == "downloaded", "download first"
        self._event("installing", {"slot": self._inactive_slot()})

        if self.fail_install:
            version = self.slots[self.active_slot]
            res = self._event(
                "failed",
                {"reason": "post-flash health check failed: sim", "rolled_back_to": version},
            )
            self._event("rollback_complete", {"rolled_back_to": version, "slot": self.active_slot})
            self._save_state()
            return {"result": "failed", "rolled_back_to": version, "halted": res.get("halted_batch_ids", [])}

        target_version = self._offer["version"]
        target_slot = self._inactive_slot()
        self.slots[target_slot] = target_version
        self.active_slot = target_slot
        self.facts["current_version"] = target_version
        self._save_state()
        self._event("installed", {"version": target_version, "slot": target_slot})
        return {"result": "installed", "version": target_version}

    def _inactive_slot(self) -> str:
        return "B" if self.active_slot == "A" else "A"

    # ----- end-to-end convenience -----
    def run_cycle(self, *, fail_after_chunks: int | None = None, resume: bool = True):
        self.register()
        body = self.check_in()
        if not body.get("offered"):
            return body
        try:
            self.download(fail_after_chunks=fail_after_chunks)
        except ConnectionError:
            if not resume:
                raise
            self.check_in()
            self.download()
        return self.install()
