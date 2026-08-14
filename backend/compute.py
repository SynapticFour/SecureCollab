# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Run an HE algorithm on encrypted.bin. Writes encrypted sufficient statistics.

Pass a .secret file as the 5th argument to also write a plaintext finalized result.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algorithms import ALGORITHMS, finalize_encrypted_result
from app.services.he_service import run_computation


def main() -> None:
    algorithm = "mean"
    selected_columns: list[str] = []
    in_path = Path("encrypted.bin")
    out_path = Path("result.json")
    secret_path: Path | None = None

    args = sys.argv[1:]
    if args:
        algorithm = args[0]
    if len(args) >= 2:
        try:
            selected_columns = json.loads(args[1])
            if not isinstance(selected_columns, list):
                selected_columns = [str(selected_columns)]
        except (json.JSONDecodeError, TypeError):
            selected_columns = []
    if len(args) >= 3:
        in_path = Path(args[2])
    if len(args) >= 4:
        out_path = Path(args[3])
    if len(args) >= 5:
        secret_path = Path(args[4])

    if not in_path.exists():
        print(f"Fehler: {in_path} nicht gefunden.", file=sys.stderr)
        sys.exit(1)
    if algorithm not in ALGORITHMS:
        print(f"Unbekannter Algorithmus: {algorithm}. Erlaubt: {list(ALGORITHMS.keys())}", file=sys.stderr)
        sys.exit(1)

    try:
        result = run_computation(in_path, algorithm, selected_columns)
    except Exception as e:
        print(f"Berechnung fehlgeschlagen: {e}", file=sys.stderr)
        sys.exit(1)

    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Algorithmus '{algorithm}' ausgeführt -> {out_path} (encrypted sufficient statistics)")
    print(json.dumps(result, indent=2)[:2000])

    if secret_path and secret_path.exists():
        plain = finalize_encrypted_result(secret_path.read_bytes(), result)
        plain_path = out_path.with_name(out_path.stem + "_plain.json")
        plain_path.write_text(json.dumps(plain, indent=2), encoding="utf-8")
        print(f"Lokal entschlüsselt -> {plain_path}")
        print(json.dumps(plain, indent=2))


if __name__ == "__main__":
    main()
