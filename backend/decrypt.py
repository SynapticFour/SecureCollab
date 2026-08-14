# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Finalize an encrypted result.json with a local secret context. Never run on the server."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algorithms import finalize_encrypted_result


def format_result(data: dict) -> str:
    lines = ["========== Ergebnis (lokal entschlüsselt) =========="]
    for k, v in data.items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Rohdaten wurden auf dem Server nicht entschlüsselt.")
    return "\n".join(lines)


def main() -> None:
    result_path = Path("result.json")
    secret_path = Path("encrypted.secret")
    if len(sys.argv) >= 2:
        result_path = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        secret_path = Path(sys.argv[2])
    if not result_path.exists():
        print(f"Fehler: {result_path} nicht gefunden.", file=sys.stderr)
        sys.exit(1)
    if not secret_path.exists():
        print(f"Fehler: Secret-Datei {secret_path} nicht gefunden.", file=sys.stderr)
        sys.exit(1)
    data = json.loads(result_path.read_text(encoding="utf-8"))
    if data.get("encrypted"):
        data = finalize_encrypted_result(secret_path.read_bytes(), data)
    print(format_result(data))


if __name__ == "__main__":
    main()
