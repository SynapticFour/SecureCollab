# SPDX-License-Identifier: Apache-2.0
"""Local audit log management and verification."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import _sha3
from .http import api_get

INITIAL_HASH = "0" * 64


def _local_audit_path(institution_email: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in institution_email)
    return Path(f"{safe}_local_audit.jsonl")


def write_local_audit(institution_email: str, action: str, details: dict) -> str:
    path = _local_audit_path(institution_email)
    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    payload = {"action": action, "timestamp": ts_str, "details": details}
    payload_str = json.dumps(payload, sort_keys=True)
    entry_hash = _sha3(payload_str)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"payload": payload, "entry_hash": entry_hash}, sort_keys=True) + "\n")
    return entry_hash


def verify_audit(api_base_url: str, study_id: int, local_audit_path: str = "") -> dict:
    return verify_audit_trail(str(study_id), api_base_url)


def verify_audit_trail(study_id: str, api_base_url: str, institution_email: str = "") -> dict[str, Any]:
    data = api_get(api_base_url, f"/studies/{study_id}/audit_trail", email=institution_email)
    if not isinstance(data, list):
        return {"chain_valid": False, "own_entries_verified": False, "anomalies": ["Audit-Trail-Format ungültig"], "total_entries": 0}
    anomalies = []
    prev_hash = INITIAL_HASH
    for i, e in enumerate(data):
        entry_hash = e.get("entry_hash", "")
        previous_hash = e.get("previous_hash", "")
        if previous_hash != prev_hash:
            anomalies.append(f"Eintrag {i}: previous_hash stimmt nicht mit Vorgänger entry_hash überein.")
        ts_str = e.get("created_at", "")
        details_str = json.dumps(e.get("details") if isinstance(e.get("details"), dict) else {}, sort_keys=True)
        payload = f"{e.get('action_type', '')}{e.get('actor_email', '')}{details_str}{ts_str}{previous_hash}"
        expected = _sha3(payload)
        if entry_hash != expected:
            anomalies.append(f"Eintrag {i}: entry_hash stimmt nicht mit berechnetem Hash überein.")
        prev_hash = entry_hash
    chain_valid = len(anomalies) == 0
    own_verified = True
    if institution_email and chain_valid:
        commit_log = Path(f"{study_id}_commitments.log")
        if commit_log.exists():
            local_hashes = set()
            for line in commit_log.read_text().strip().splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("institution_email") == institution_email:
                        local_hashes.add(rec.get("commitment_hash", ""))
                except (json.JSONDecodeError, TypeError):
                    pass
            pk = api_get(api_base_url, f"/studies/{study_id}/public_key", email=institution_email)
            server_commitments = [
                u.get("commitment_hash")
                for u in (pk.get("upload_commitments", []) if isinstance(pk, dict) else [])
                if u.get("institution_email") == institution_email
            ]
            if local_hashes and not all(c in local_hashes for c in server_commitments):
                own_verified = False
                anomalies.append("Mindestens ein eigener Upload-Commitment auf dem Server fehlt im lokalen Log oder weicht ab.")
    return {
        "chain_valid": chain_valid,
        "own_entries_verified": own_verified,
        "anomalies": anomalies,
        "total_entries": len(data),
    }
