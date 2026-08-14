# SPDX-License-Identifier: Apache-2.0
"""Thin wrapper so `python sdk/cli.py` still works."""
from securecollab.cli import main

if __name__ == "__main__":
    raise SystemExit(main() or 0)
