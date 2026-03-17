# SPDX-License-Identifier: Apache-2.0
"""Tests for demo seed script: run seed and verify DB state."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


def _run_seed_in_subprocess(db_path: Path, uploads_dir: Path) -> subprocess.CompletedProcess:
    """Run scripts.seed_demo in a subprocess with isolated DB and uploads."""
    env = os.environ.copy()
    db_url = f"sqlite:///{db_path}"
    env["SECURECOLLAB_DATABASE_URL"] = db_url
    env["DATABASE_URL"] = db_url
    env["SECURECOLLAB_UPLOADS_DIR"] = str(uploads_dir)
    env["UPLOAD_DIR"] = str(uploads_dir)
    backend_dir = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "scripts.seed_demo"],
        cwd=str(backend_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


def test_seed_demo_creates_study_and_participants(tmp_path):
    """Running seed_demo creates one demo study and two participants."""
    db_path = tmp_path / "seed_test.db"
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    result = _run_seed_in_subprocess(db_path, uploads_dir)
    assert result.returncode == 0, (result.stdout or "") + (result.stderr or "")

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT id, name, status FROM studies WHERE name = 'Demo Study'")
        rows = cur.fetchall()
        assert len(rows) == 1
        study_id = rows[0][0]
        assert rows[0][2] == "active"

        cur = conn.execute("SELECT COUNT(*) FROM study_participants WHERE study_id = ?", (study_id,))
        assert cur.fetchone()[0] == 2

        cur = conn.execute("SELECT COUNT(*) FROM study_protocol WHERE study_id = ? AND status = 'finalized'", (study_id,))
        assert cur.fetchone()[0] == 1

        cur = conn.execute("SELECT COUNT(*) FROM jobs WHERE study_id = ? AND status = 'pending_approval'", (study_id,))
        assert cur.fetchone()[0] >= 1
    finally:
        conn.close()


def test_seed_demo_idempotent(tmp_path):
    """Running seed_demo twice does not duplicate the demo study."""
    db_path = tmp_path / "seed_idem.db"
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    r1 = _run_seed_in_subprocess(db_path, uploads_dir)
    assert r1.returncode == 0

    r2 = _run_seed_in_subprocess(db_path, uploads_dir)
    assert r2.returncode == 0

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT COUNT(*) FROM studies WHERE name = 'Demo Study'")
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()
