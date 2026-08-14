# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest

from securecollab.exceptions import CryptoError, SchemaError


def test_generate_contexts():
    pytest.importorskip("tenseal")
    from securecollab.crypto import generate_contexts

    public_ctx, secret_ctx = generate_contexts()
    assert isinstance(public_ctx, (bytes, bytearray)) and len(public_ctx) > 0
    assert isinstance(secret_ctx, (bytes, bytearray)) and len(secret_ctx) > 0
    assert secret_ctx != public_ctx


def test_save_secret_key_refuses_empty_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from securecollab.crypto import save_secret_key

    with pytest.raises(CryptoError, match="empty"):
        save_secret_key(b"not-a-real-context", "inst@test.com", "")


def test_save_and_load_secret_key(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.chdir(tmp_path)
    from securecollab.crypto import load_secret_key, save_secret_key

    path = save_secret_key(b"secret-bytes-payload", "inst@test.com", "correct-horse")
    assert Path(path).exists()
    assert load_secret_key("inst@test.com", "correct-horse") == b"secret-bytes-payload"


def test_dump_bundle_refuses_secret_context():
    from securecollab.bundle import BundleError, dump_bundle

    with pytest.raises(BundleError, match="secret_context"):
        dump_bundle({
            "public_context": b"pub",
            "secret_context": b"sec",
            "vectors": {"x": b"ct"},
            "columns": ["x"],
            "n": 1,
        })
