"""Terminal-side trust store.

This is the code that would live on the device. It is deliberately
transport-agnostic: feed it the envelopes the service hands out at check-in.

Invariants
----------
* The accepted root version and the highest accepted security counter are
  persisted to flash and survive power loss / process restart.
* A root chain is applied **all or nothing**: every envelope is verified
  first; only then is trust persisted, so a crash or a bad link can never
  leave the device on a half-applied root. Re-running the same chain is
  idempotent and converges.
* Versions must be strictly consecutive from the trusted anchor: a missing
  intermediate authorization fails closed (gap, bad signature, expiry,
  revoked signer, backwards version).
* A release is accepted only when its signed counter is strictly greater
  than the highest counter ever accepted — the anti-rollback watermark.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.security import (
    RootView,
    TrustError,
    normalize_root,
    verify_release_envelope,
    verify_root_envelope,
)


class TrustRejected(Exception):
    """Device refused content before its critical write phase."""

    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason if detail is None else f"{reason}:{detail}")
        self.reason = reason


@dataclass
class TerminalTrustState:
    model: str
    root_version: int = 0          # 0 == unprovisioned (factory anchor not yet received)
    root_envelope: dict | None = None
    highest_counter: int = 0

    def view(self) -> RootView | None:
        if self.root_envelope is None:
            return None
        return normalize_root(self.root_envelope["signed"])


class TerminalTrust:
    """File-backed trust store. Writes go through a temp file + atomic
    replace, so an interrupted persist cannot tear the trust state."""

    def __init__(self, path: Path, model: str):
        self.path = Path(path)
        self.state = TerminalTrustState(model=model)
        self._load()

    # ----- persistence -----
    def _load(self) -> None:
        if self.path.exists():
            raw = json.loads(self.path.read_text())
            self.state = TerminalTrustState(
                model=raw["model"],
                root_version=raw.get("root_version", 0),
                root_envelope=raw.get("root_envelope"),
                highest_counter=raw.get("highest_counter", 0),
            )

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({
            "model": self.state.model,
            "root_version": self.state.root_version,
            "root_envelope": self.state.root_envelope,
            "highest_counter": self.state.highest_counter,
        }, sort_keys=True))
        os.replace(tmp, self.path)

    @property
    def root_version(self) -> int:
        return self.state.root_version

    @property
    def highest_counter(self) -> int:
        return self.state.highest_counter

    # ----- root rotations -----
    def apply_root_chain(
        self,
        envelopes: list[dict],
        *,
        now: datetime | None = None,
    ) -> int:
        """Verify and apply a continuous chain of root envelopes.

        Accepts the factory anchor (v1, self-signed) exactly once; afterwards
        each envelope must be version N+1 dual-authorized by N and N+1.
        Nothing is persisted unless EVERY envelope verifies.
        """
        if not envelopes:
            return self.state.root_version

        candidate_env = self.state.root_envelope
        candidate_view = self.state.view()
        candidate_version = self.state.root_version

        # Idempotent catch-up: a server that did not record our last applied
        # version may resend anchors. Skip anything already trusted, then the
        # remainder must be strictly consecutive.
        pending = []
        for envelope in envelopes:
            try:
                v = normalize_root(envelope["signed"]).version
            except (KeyError, TypeError):
                raise TrustRejected("bad_metadata", "envelope") from None
            if v <= candidate_version:
                continue
            pending.append(envelope)

        for envelope in pending:
            try:
                view = verify_root_envelope(
                    envelope,
                    trusted=candidate_view,
                    model=self.state.model,
                    now=now or datetime.now().astimezone(),
                )
            except TrustError as e:
                # Fail closed: leave the persisted trust exactly as it was.
                raise TrustRejected(e.reason, str(e)) from None
            if view.version != candidate_version + 1:
                # verify_root_envelope already enforces this, but keep the
                # invariant explicit for chains handed to us out of order.
                raise TrustRejected(
                    "root_chain_gap",
                    f"{candidate_version}->{view.version}",
                )
            candidate_env = envelope
            candidate_view = view
            candidate_version = view.version

        self.state.root_envelope = candidate_env
        self.state.root_version = candidate_version
        self._persist()
        return candidate_version

    # ----- release verification -----
    def verify_release(
        self,
        envelope: dict | None,
        *,
        artifact_sha256: str | None = None,
        version: str | None = None,
        now: datetime | None = None,
    ):
        """Full pre-critical-write evaluation. Raises TrustRejected on any
        failure; returns the signed claims otherwise (without mutating state)."""
        view = self.state.view()
        if view is None:
            raise TrustRejected("no_trust_anchor")
        if envelope is None:
            raise TrustRejected("unsigned_release")
        try:
            claims = verify_release_envelope(
                envelope, root=view, now=now or datetime.now().astimezone()
            )
        except TrustError as e:
            raise TrustRejected(e.reason, str(e)) from None

        if claims.counter <= self.state.highest_counter:
            raise TrustRejected(
                "counter_rollback",
                f"{claims.counter}<={self.state.highest_counter}",
            )
        if artifact_sha256 is not None and claims.artifact_digest != "sha256:" + artifact_sha256:
            raise TrustRejected("artifact_digest_mismatch")
        if version is not None and claims.version != str(version):
            raise TrustRejected("release_version_mismatch")
        return claims

    def commit_accepted_release(self, counter: int, root_version: int) -> None:
        """Persist the watermark ONLY after a successful, health-checked boot
        on the new firmware (never before the critical write succeeded)."""
        self.state.highest_counter = max(self.state.highest_counter, counter)
        self.state.root_version = max(self.state.root_version, root_version)
        self._persist()
