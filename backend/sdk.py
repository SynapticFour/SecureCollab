# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Deprecated shim. The Client SDK lives in ../sdk (package `securecollab`).

    python sdk.py generate-key --email you@org.example
    # equivalent to:
    python -m securecollab.cli generate-key --email you@org.example
"""
from __future__ import annotations

import sys
from pathlib import Path

_SDK_ROOT = Path(__file__).resolve().parent.parent / "sdk"
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

from securecollab.audit import verify_audit_trail, write_local_audit  # noqa: E402
from securecollab.cli import main as _cli_main  # noqa: E402
from securecollab.crypto import generate_key_share, load_secret_key, save_secret_key  # noqa: E402
from securecollab.ops import (  # noqa: E402
    analyze_local_schema,
    compute_decryption_share,
    encrypt_and_upload,
    generate_study_report,
    run_dry_run,
    verify_study_public_key,
)
from securecollab.schema import negotiate_schema  # noqa: E402

__all__ = [
    "analyze_local_schema",
    "compute_decryption_share",
    "encrypt_and_upload",
    "generate_key_share",
    "generate_study_report",
    "load_secret_key",
    "negotiate_schema",
    "run_dry_run",
    "save_secret_key",
    "verify_audit_trail",
    "verify_study_public_key",
    "write_local_audit",
]


def _cli():
    return _cli_main()


if __name__ == "__main__":
    raise SystemExit(_cli() or 0)
