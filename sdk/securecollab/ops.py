# SPDX-License-Identifier: Apache-2.0
"""Study workflow: verify key, encrypt+upload, authorization shares, reports."""
from __future__ import annotations

import base64
import getpass
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from .audit import write_local_audit
from .crypto import _secret_key_path, _sha3, encrypt_csv_with_public_context, load_secret_key
from .exceptions import APIError, CryptoError
from .http import api_get, api_post
from .schema import analyze_csv_columns


def analyze_local_schema(csv_path: str) -> dict[str, Any]:
    try:
        return analyze_csv_columns(csv_path)
    except Exception as e:
        return {"columns": [], "error": str(e)}


def verify_study_public_key(study_id: str, api_base_url: str, email: str = "") -> dict[str, Any]:
    data = api_get(api_base_url, f"/studies/{study_id}/public_key", email=email)
    if not isinstance(data, dict):
        raise APIError("Ungültige public_key-Antwort")
    combined_b64 = data.get("combined_public_key") or ""
    server_fp = data.get("public_key_fingerprint") or ""
    participants = data.get("upload_commitments", [])
    if not combined_b64:
        return {
            "verified": False,
            "fingerprint": "",
            "participants": participants,
            "key_model": data.get("key_model"),
            "error": "Kein Public Key auf dem Server (Study evtl. noch nicht aktiv).",
        }
    raw = base64.b64decode(combined_b64)
    local_fp = _sha3(raw)
    return {
        "verified": local_fp == server_fp,
        "fingerprint": local_fp,
        "participants": participants,
        "key_model": data.get("key_model"),
    }


def run_dry_run(
    csv_path: str,
    study_id: str,
    institution_email: str,
    api_base_url: str,
) -> dict[str, Any]:
    path = Path(csv_path)
    if not path.exists():
        return {"schema_valid": False, "issues": ["Datei nicht gefunden"], "algorithms_tested": []}
    try:
        resp = api_post(
            api_base_url,
            f"/studies/{study_id}/synthetic/upload",
            form={"institution_email": institution_email},
            file_path=path,
            file_field="file",
            email=institution_email,
        )
    except Exception as e:
        return {"schema_valid": False, "issues": [str(e)], "algorithms_tested": []}
    write_local_audit(
        institution_email,
        "dry_run_completed",
        {"study_id": study_id, "schema_valid": resp.get("schema_valid")},
    )
    return resp


def encrypt_and_upload(
    csv_path: str,
    study_id: str,
    institution_email: str,
    api_base_url: str,
) -> dict[str, Any]:
    csv_file = Path(csv_path)
    if not csv_file.exists():
        return {"commitment_hash": "", "verified": False, "columns_encrypted": [], "error": "CSV-Datei nicht gefunden."}
    out = verify_study_public_key(study_id, api_base_url, email=institution_email)
    if not out.get("verified"):
        return {
            "commitment_hash": "",
            "verified": False,
            "columns_encrypted": [],
            "error": out.get("error") or "Study Public Key konnte nicht verifiziert werden.",
        }
    fingerprint = out["fingerprint"]
    pk = api_get(api_base_url, f"/studies/{study_id}/public_key", email=institution_email)
    if not isinstance(pk, dict):
        return {"commitment_hash": "", "verified": False, "columns_encrypted": [], "error": "Public Key ungültig."}
    combined_b64 = pk.get("combined_public_key") or ""
    ctx_bytes = base64.b64decode(combined_b64)
    try:
        blob, numeric_columns, _n = encrypt_csv_with_public_context(csv_file, ctx_bytes)
    except CryptoError as e:
        return {"commitment_hash": "", "verified": False, "columns_encrypted": [], "error": str(e)}
    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    commitment_hash = _sha3(blob, fingerprint, ts_str, institution_email)
    commit_log_path = Path(f"{study_id}_commitments.log")
    with open(commit_log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "timestamp": ts_str,
            "commitment_hash": commitment_hash,
            "dataset": csv_file.name,
            "institution_email": institution_email,
        }) + "\n")
    tmp_file = Path(f"upload_{study_id}_{os.getpid()}.bin")
    tmp_file.write_bytes(blob)
    try:
        resp = api_post(
            api_base_url,
            f"/studies/{study_id}/upload_dataset",
            form={
                "institution_email": institution_email,
                "dataset_name": csv_file.stem,
                "columns": json.dumps(numeric_columns),
                "commitment_timestamp": ts_str,
            },
            file_path=tmp_file,
            file_field="file",
            email=institution_email,
        )
    finally:
        tmp_file.unlink(missing_ok=True)
    server_commitment = resp.get("commitment_hash", "")
    verified = server_commitment == commitment_hash
    write_local_audit(
        institution_email,
        "encrypt_and_upload",
        {
            "study_id": study_id,
            "commitment_hash": commitment_hash,
            "verified": verified,
            "columns_encrypted": numeric_columns,
        },
    )
    return {"commitment_hash": commitment_hash, "verified": verified, "columns_encrypted": numeric_columns}


def compute_decryption_share(
    study_id: str,
    job_id: str,
    institution_email: str,
    api_base_url: str,
    password: str | None = None,
) -> dict[str, Any]:
    """Submit an authorization share to release the encrypted result.

    This is not a cryptographic partial decrypt. The secret key is loaded only
    to prove the institution still holds it; the share itself is an attestation.
    """
    if not _secret_key_path(institution_email).exists():
        return {
            "share_submitted": False,
            "job_id": job_id,
            "error": "Lokaler Secret Key nicht gefunden. Zuerst generate-key ausführen.",
        }
    if password is None:
        password = getpass.getpass("Passwort für den Secret Key: ")
    try:
        secret_ctx = load_secret_key(institution_email, password)
    except Exception:
        return {
            "share_submitted": False,
            "job_id": job_id,
            "error": "Entschlüsselung des Secret Keys fehlgeschlagen (falsches Passwort?).",
        }
    share_fingerprint = _sha3(secret_ctx)[:32]
    payload = f"{job_id}{institution_email}{share_fingerprint}{datetime.now(timezone.utc).isoformat()}"
    share_bytes = _sha3(payload).encode("ascii")
    decryption_share_b64 = base64.b64encode(share_bytes).decode("ascii")
    try:
        api_post(
            api_base_url,
            f"/studies/{study_id}/jobs/{job_id}/submit_decryption_share",
            data={"institution_email": institution_email, "decryption_share": decryption_share_b64},
            email=institution_email,
        )
    except (HTTPError, URLError) as e:
        return {"share_submitted": False, "job_id": job_id, "error": str(e)}
    write_local_audit(institution_email, "decryption_share_submitted", {"study_id": study_id, "job_id": job_id})
    return {"share_submitted": True, "job_id": job_id}


def generate_study_report(study_id: str, api_base_url: str, institution_email: str = "") -> str:
    from .audit import verify_audit_trail

    protocol = api_get(api_base_url, f"/studies/{study_id}/protocol", email=institution_email)
    if not isinstance(protocol, dict):
        raise APIError("Ungültiges Protocol")
    audit_result = verify_audit_trail(study_id, api_base_url, institution_email)
    meta = protocol.get("study_metadata", {})
    lines = [
        f"# Verifikationsbericht Study {study_id}",
        "",
        "## Study-Parameter",
        f"- Name: {meta.get('name', '')}",
        f"- Status: {meta.get('status', '')}",
        f"- Threshold: {meta.get('threshold_t', '')} von {meta.get('threshold_n', '')}",
        f"- Public-Key-Fingerprint: `{meta.get('public_key_fingerprint', '')}`",
        "",
        "## Teilnehmer",
    ]
    for p in protocol.get("participants", []):
        lines.append(f"- {p.get('institution_name', '')} ({p.get('institution_email', '')})")
    lines.extend([
        "",
        "## Erlaubte Algorithmen",
        "- " + ", ".join(protocol.get("allowed_algorithms", [])),
        "",
        "## Upload-Commitments (Server)",
    ])
    for d in protocol.get("datasets", []):
        lines.append(f"- {d.get('dataset_name', '')} / {d.get('institution_email', '')}: `{d.get('commitment_hash', '')[:24]}...`")
    lines.extend([
        "",
        "## Audit-Trail-Verifikation",
        f"- Kette gültig: **{'Ja' if audit_result['chain_valid'] else 'Nein'}**",
        f"- Eigene Einträge verifiziert: **{'Ja' if audit_result['own_entries_verified'] else 'Nein'}**",
        f"- Anzahl Einträge: {audit_result['total_entries']}",
    ])
    if audit_result.get("anomalies"):
        lines.append("")
        lines.append("### Anomalien")
        for a in audit_result["anomalies"]:
            lines.append(f"- {a}")
    lines.extend([
        "",
        "## Kryptographische Garantien (Kurz)",
        "- Rohdaten verlassen die Institution nur verschlüsselt (Study Public Key).",
        "- Der Server entschlüsselt nicht; Ergebnisse sind Ciphertexts bis zur lokalen Finalisierung.",
        "- Der Commitment bindet Ciphertext, Key-Fingerprint, Zeit und Institution.",
        "- Der Audit Trail ist durch Hash-Verkettung manipulationssicher.",
        "- Eine Ergebnis-Freigabe (Share) ist eine Autorisierung, keine partielle Entschlüsselung.",
        "",
        f"*Erstellt: {datetime.now(timezone.utc).isoformat()}*",
    ])
    report = "\n".join(lines)
    out_path = Path(f"{study_id}_verification_report.md")
    out_path.write_text(report, encoding="utf-8")
    return str(out_path)


def finalize_encrypted_result(secret_context_bytes: bytes, result: dict[str, Any]) -> dict[str, Any]:
    """Decrypt encrypted sufficient statistics locally. Uses backend algorithms if present."""
    backend = Path(__file__).resolve().parents[2] / "backend"
    if str(backend) not in __import__("sys").path:
        __import__("sys").path.insert(0, str(backend))
    from algorithms import finalize_encrypted_result as _finalize

    return _finalize(secret_context_bytes, result)
