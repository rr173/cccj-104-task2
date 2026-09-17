"""Deterministic serialization for signed payloads.

Canonical JSON (JCS-style, tailored to the value domain we actually use):

* dict keys are UTF-8 sorted and emitted in that order;
* no insignificant whitespace;
* separators are fixed (``","`` / ``":"``);
* ensure_ascii=False so a byte is a byte regardless of how a version string
  was quoted — hashes/signatures stay stable across Python JSON implementations;
* datetimes are expressed as UTC ISO-8601 with an explicit ``Z`` suffix.

Everything that gets signed or digested goes through :func:`canonical_bytes`,
so "re-serialize and sign" on the publisher and "serialize and verify" on the
terminal always agree byte-for-byte.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

_ALLOWED = (str, int, bool, float, type(None), dict, list, tuple)


def _norm(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in sorted(value.items(), key=lambda kv: kv[0].encode("utf-8"))}
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    if not isinstance(value, _ALLOWED):
        raise TypeError(f"cannot canonically serialize {type(value)!r}")
    if isinstance(value, float):
        # NaN/Infinity are non-deterministic across parsers; reject up front.
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite float in signed payload")
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _norm(value),
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def normalize_scalar(value: Any) -> Any:
    """Project a scalar/dict/list onto the canonical JSON representation's
    value domain (e.g. an aware datetime -> UTC ``...Z`` string)."""
    return _norm(value)
