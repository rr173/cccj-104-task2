"""Acceptance: trust guarantees survive a real process restart.

Two separate Python interpreters share one on-disk DB + artifact store +
keyring. Phase 1 installs a signed release; after the process exits, phase 2
boots a fresh server and proves the anti-rollback watermark, root chain and
failure receipts are still enforced.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Prefer the project virtualenv's interpreter (dependencies live there).
_VENV_PY = ROOT / ".venv" / "bin" / "python"
PYTHON = str(_VENV_PY) if _VENV_PY.exists() else sys.executable


def _run_phase(tmp_path, phase):
    env = {
        "DATABASE_URL": f"sqlite:///{tmp_path / 'restart.db'}",
        "STORAGE_ROOT": str(tmp_path / "art"),
        "KEYS_ROOT": str(tmp_path / "keys"),
        "CHUNK_SIZE": "64",
        "FAILURE_THRESHOLD": "0.5",
        "FAILURE_MIN_SAMPLE": "2",
        "SEED_DEMO": "false",
        "PYTHONPATH": str(ROOT),
        "FOTA_RESTART_PHASE": phase,
    }
    proc = subprocess.run(
        [PYTHON, str(ROOT / "tests" / "restart_runner.py")],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert proc.returncode == 0, f"phase {phase} failed:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_watermark_root_and_receipts_survive_restart(tmp_path):
    p1 = _run_phase(tmp_path, "1")
    assert p1["ok"] is True
    assert p1["highest_counter"] == 1

    # Fresh interpreter (simulates reboot / service redeploy).
    p2 = _run_phase(tmp_path, "2")
    assert p2["root_version"] == 1
    assert p2["rels"] == 1
    assert p2["gate_status"] == 422
    assert p2["gate_reason"] == "counter_rollback"
    assert p2["has_rollback_receipt"] is True
