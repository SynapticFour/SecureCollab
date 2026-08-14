# SPDX-License-Identifier: Apache-2.0
"""SecureCollab Client SDK for local encryption and API interaction."""
from .audit import verify_audit, verify_audit_trail, write_local_audit
from .client import SecureCollabClient
from .crypto import generate_contexts, generate_key_share, load_secret_key, save_secret_key
from .exceptions import APIError, CryptoError, SchemaError, SecureCollabSDKError
from .ops import (
    analyze_local_schema,
    compute_decryption_share,
    encrypt_and_upload,
    finalize_encrypted_result,
    generate_study_report,
    run_dry_run,
    verify_study_public_key,
)
from .schema import analyze_csv_columns, negotiate_schema

__all__ = [
    "APIError",
    "CryptoError",
    "SchemaError",
    "SecureCollabClient",
    "SecureCollabSDKError",
    "analyze_csv_columns",
    "analyze_local_schema",
    "compute_decryption_share",
    "encrypt_and_upload",
    "finalize_encrypted_result",
    "generate_contexts",
    "generate_key_share",
    "generate_study_report",
    "load_secret_key",
    "negotiate_schema",
    "run_dry_run",
    "save_secret_key",
    "verify_audit",
    "verify_audit_trail",
    "verify_study_public_key",
    "write_local_audit",
]
