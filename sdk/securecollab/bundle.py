# SPDX-License-Identifier: Apache-2.0
"""Safe HE bundle codec: JSON + base64 TenSEAL bytes. Never pickle. Never secret keys."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

BUNDLE_VERSION = 1
_PICKLE_MAGIC = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")


class BundleError(ValueError):
    """Uploaded or on-disk bundle is not a valid SecureCollab ciphertext package."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except Exception as e:
        raise BundleError("Invalid base64 in bundle") from e


def dump_bundle(bundle: dict[str, Any]) -> bytes:
    """Serialize an in-memory bundle (bytes vectors) to the on-disk JSON format.

    secret_context is never written.
    """
    if "secret_context" in bundle:
        raise BundleError("Refusing to serialize a bundle that contains secret_context")
    public_ctx = bundle.get("public_context")
    if not isinstance(public_ctx, (bytes, bytearray)):
        raise BundleError("Bundle missing public_context bytes")
    n = bundle.get("n")
    if not isinstance(n, int) or n < 0:
        raise BundleError("Bundle missing integer n")
    columns = bundle.get("columns", [])
    if isinstance(columns, str):
        try:
            columns = json.loads(columns)
        except (json.JSONDecodeError, TypeError) as e:
            raise BundleError("Bundle columns is not valid JSON") from e
    if not isinstance(columns, list):
        raise BundleError("Bundle columns must be a list")
    vectors = bundle.get("vectors")
    if not isinstance(vectors, dict) or not vectors:
        enc = bundle.get("encrypted_vector")
        if not isinstance(enc, (bytes, bytearray)):
            raise BundleError("Bundle needs vectors dict or encrypted_vector bytes")
        vectors_out = {"_default": _b64e(bytes(enc))}
        if not columns:
            columns = ["_default"]
    else:
        vectors_out = {}
        for k, v in vectors.items():
            if not isinstance(v, (bytes, bytearray)):
                raise BundleError(f"Vector '{k}' is not raw TenSEAL bytes")
            vectors_out[str(k)] = _b64e(bytes(v))
    payload = {
        "v": BUNDLE_VERSION,
        "n": n,
        "columns": [str(c) for c in columns],
        "public_context": _b64e(bytes(public_ctx)),
        "vectors": vectors_out,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def load_bundle(source: dict[str, Any] | str | Path | bytes) -> dict[str, Any]:
    """Load a bundle from a dict, path, or bytes. Rejects pickle and secret_context."""
    if isinstance(source, dict):
        obj: dict[str, Any] = source
    else:
        raw = source.read_bytes() if isinstance(source, Path) else (
            Path(source).read_bytes() if isinstance(source, str) else source
        )
        if raw.startswith(_PICKLE_MAGIC) or raw[:1] == b"\x80":
            raise BundleError("Pickle bundles are not accepted")
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise BundleError("Bundle is not valid JSON") from e
    if not isinstance(obj, dict):
        raise BundleError("Bundle root must be an object")
    if "secret_context" in obj:
        raise BundleError("Bundles must not contain secret_context")
    if "public_context" not in obj:
        raise BundleError("Bundle missing public_context")
    public_ctx = obj["public_context"]
    if isinstance(public_ctx, str):
        public_ctx = _b64d(public_ctx)
    elif not isinstance(public_ctx, (bytes, bytearray)):
        raise BundleError("public_context must be base64 or bytes")
    n = obj.get("n")
    if not isinstance(n, int):
        raise BundleError("Bundle missing 'n' (number of rows)")
    columns = obj.get("columns", [])
    if isinstance(columns, str):
        try:
            columns = json.loads(columns)
        except (json.JSONDecodeError, TypeError) as e:
            raise BundleError("columns is not valid JSON") from e
    if not isinstance(columns, list):
        columns = []
    vectors_in = obj.get("vectors")
    vectors: dict[str, bytes] = {}
    if isinstance(vectors_in, dict) and vectors_in:
        for k, v in vectors_in.items():
            if isinstance(v, str):
                vectors[str(k)] = _b64d(v)
            elif isinstance(v, (bytes, bytearray)):
                vectors[str(k)] = bytes(v)
            else:
                raise BundleError(f"Vector '{k}' has unsupported type")
    elif obj.get("encrypted_vector") is not None:
        enc = obj["encrypted_vector"]
        if isinstance(enc, str):
            enc = _b64d(enc)
        if not isinstance(enc, (bytes, bytearray)):
            raise BundleError("encrypted_vector is not bytes")
        name = str(columns[0]) if columns else "_default"
        vectors[name] = bytes(enc)
        if not columns:
            columns = [name]
    else:
        raise BundleError("Bundle has no vectors")
    return {
        "public_context": bytes(public_ctx),
        "vectors": vectors,
        "columns": json.dumps([str(c) for c in columns]),
        "n": n,
    }
