# SPDX-License-Identifier: Apache-2.0
"""HE key generation, Fernet-protected secret storage, local encrypt. No XOR fallback."""
from __future__ import annotations

import base64
import csv
import hashlib
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from .bundle import dump_bundle
from .exceptions import CryptoError

try:
    import tenseal as ts
except ImportError:
    ts = None  # type: ignore

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    Fernet = None  # type: ignore
    crypto_hashes = None  # type: ignore
    PBKDF2HMAC = None  # type: ignore

PBKDF2_ITERATIONS = 600_000
SECRET_KEY_SALT_LEN = 16
FERNET_MAGIC = b"SCF1"
HTTP_TIMEOUT = 30


def _sha3(*parts: bytes | str) -> str:
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p.encode("utf-8") if isinstance(p, str) else p)
    return h.hexdigest()


def _secret_key_path(institution_email: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in institution_email)
    return Path(f"{safe}_secret.key")


def generate_contexts() -> tuple[bytes, bytes]:
    """Return (public_context_bytes, secret_context_bytes)."""
    if ts is None:
        raise CryptoError("TenSEAL is not installed")
    ctx = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60],
    )
    ctx.generate_galois_keys()
    ctx.global_scale = 2**40
    secret_ctx = ctx.serialize(save_secret_key=True)
    ctx.make_context_public()
    return ctx.serialize(), secret_ctx


def save_secret_key(context_bytes: bytes, institution_email: str, password: str) -> Path:
    if Fernet is None or PBKDF2HMAC is None or crypto_hashes is None:
        raise CryptoError("cryptography is required to store secret keys (no XOR fallback)")
    if not password:
        raise CryptoError("Password must not be empty")
    path = _secret_key_path(institution_email)
    salt = os.urandom(SECRET_KEY_SALT_LEN)
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    encrypted_context = Fernet(key).encrypt(context_bytes)
    path.write_bytes(FERNET_MAGIC + salt + encrypted_context)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def load_secret_key(institution_email: str, password: str) -> bytes:
    if Fernet is None or PBKDF2HMAC is None or crypto_hashes is None:
        raise CryptoError("cryptography is required to load secret keys")
    path = _secret_key_path(institution_email)
    if not path.exists():
        raise FileNotFoundError(f"Secret key file not found: {path}")
    raw = path.read_bytes()
    if not raw.startswith(FERNET_MAGIC) or len(raw) <= len(FERNET_MAGIC) + SECRET_KEY_SALT_LEN:
        raise CryptoError("Secret key file is not in Fernet format (legacy XOR files are not supported)")
    salt = raw[len(FERNET_MAGIC):len(FERNET_MAGIC) + SECRET_KEY_SALT_LEN]
    encrypted_context = raw[len(FERNET_MAGIC) + SECRET_KEY_SALT_LEN:]
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key).decrypt(encrypted_context)


def generate_key_share(institution_email: str, password: str) -> dict[str, Any]:
    if ts is None:
        raise CryptoError("TenSEAL is not installed")
    if not password:
        raise CryptoError("Password must not be empty")
    public_ctx, secret_ctx = generate_contexts()
    key_fingerprint = _sha3(public_ctx)
    public_b64 = base64.b64encode(public_ctx).decode("ascii")
    path = save_secret_key(secret_ctx, institution_email, password)
    return {
        "public_key_share": public_b64,
        "key_fingerprint": key_fingerprint,
        "secret_key_file": str(path),
    }


def encrypt_csv_with_public_context(csv_path: Path, public_ctx_bytes: bytes) -> tuple[bytes, list[str], int]:
    """Encrypt numeric columns under a public CKKS context. Returns (bundle_bytes, columns, n)."""
    if ts is None:
        raise CryptoError("TenSEAL is not installed")
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
        raise CryptoError("CSV is empty")
    numeric = [k for k in keys if k not in dropped]
    if not numeric:
        raise CryptoError("No numeric columns")
    ctx = ts.context_from(public_ctx_bytes)
    vectors = {col: ts.ckks_vector(ctx, cols[col]).serialize() for col in numeric}
    blob = dump_bundle({
        "public_context": public_ctx_bytes,
        "vectors": vectors,
        "columns": numeric,
        "n": n,
    })
    return blob, numeric, n
