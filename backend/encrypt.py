# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Encrypt a CSV locally. The secret key is never written into the .bin."""
from __future__ import annotations

import base64
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import tenseal as ts
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.services.bundle import dump_bundle


def _read_numeric_columns(csv_path: Path) -> tuple[list[str], dict[str, list[float]], int]:
    cols: dict[str, list[float]] = defaultdict(list)
    dropped: set[str] = set()
    keys: list[str] | None = None
    n = 0
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            n += 1
            if keys is None:
                keys = list(row.keys())
            for k in keys:
                if k in dropped:
                    continue
                val = row.get(k, "")
                if val is None or val == "":
                    dropped.add(k)
                    cols.pop(k, None)
                    continue
                try:
                    cols[k].append(float(val))
                except (ValueError, TypeError):
                    dropped.add(k)
                    cols.pop(k, None)
    if not keys or n == 0:
        raise SystemExit("Fehler: Keine Daten in CSV.")
    numeric = [k for k in keys if k not in dropped]
    if not numeric:
        raise SystemExit("Fehler: Keine numerischen Spalten gefunden.")
    return numeric, {k: cols[k] for k in numeric}, n


def main() -> None:
    csv_path = Path("sample_clinical_data.csv")
    out_path = Path("encrypted.bin")
    if len(sys.argv) >= 2:
        csv_path = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        out_path = Path(sys.argv[2])
    if not csv_path.exists():
        print(f"Fehler: {csv_path} nicht gefunden.", file=sys.stderr)
        sys.exit(1)

    numeric_columns, column_vectors, n = _read_numeric_columns(csv_path)
    print("Gefundene und verschlüsselte Spalten:", ", ".join(numeric_columns))

    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60],
    )
    context.generate_galois_keys()
    context.global_scale = 2**40
    secret_path = out_path.with_suffix(".secret")
    raw_secret = context.serialize(save_secret_key=True)
    password = (sys.argv[3] if len(sys.argv) >= 4 else "").strip()
    if not password:
        raise SystemExit(
            "Fehler: Passwort als drittes Argument erforderlich "
            "(secret is Fernet-wrapped; never written in plaintext)."
        )
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=crypto_hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    secret_path.write_bytes(b"SCF1" + salt + Fernet(key).encrypt(raw_secret))
    try:
        secret_path.chmod(0o600)
    except OSError:
        pass
    vectors_serialized = {
        col: ts.ckks_vector(context, column_vectors[col]).serialize()
        for col in numeric_columns
    }
    context.make_context_public()
    bundle = {
        "public_context": context.serialize(),
        "vectors": vectors_serialized,
        "columns": numeric_columns,
        "n": n,
    }
    out_path.write_bytes(dump_bundle(bundle))
    print(f"Encrypted {len(numeric_columns)} columns, {n} rows -> {out_path}")
    print(f"Secret key written to {secret_path} (not uploaded).")
    print("Columns JSON (für Upload Form-Feld 'columns'):")
    print(json.dumps(numeric_columns))


if __name__ == "__main__":
    main()
