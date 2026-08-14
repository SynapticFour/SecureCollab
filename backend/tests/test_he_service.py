# SPDX-License-Identifier: Apache-2.0
"""Unit tests for HE operations. Independent of running server."""
import pytest

from app.core.algorithms import ALGORITHM_REGISTRY
from app.services.bundle import BundleError, dump_bundle, load_bundle

try:
    import tenseal as ts
    import numpy as np
    TENSEAL_AVAILABLE = True
except ImportError:
    TENSEAL_AVAILABLE = False


def _make_simple_bundle(values: list[float], col_name: str = "col1"):
    """Build a public-only CKKS bundle plus the secret context (kept separate)."""
    if not TENSEAL_AVAILABLE:
        pytest.skip("tenseal not installed")
    ctx = ts.context(ts.SCHEME_TYPE.CKKS, 8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    ctx.global_scale = 2**40
    ctx.generate_galois_keys()
    secret = ctx.serialize(save_secret_key=True)
    enc = ts.ckks_vector(ctx, values)
    ctx.make_context_public()
    bundle = {
        "public_context": ctx.serialize(),
        "vectors": {col_name: enc.serialize()},
        "columns": f'["{col_name}"]',
        "n": len(values),
    }
    return bundle, secret


def _make_two_column_bundle(col1: list[float], col2: list[float], name1: str = "a", name2: str = "b"):
    if not TENSEAL_AVAILABLE:
        pytest.skip("tenseal not installed")
    n = len(col1)
    assert len(col2) == n
    ctx = ts.context(ts.SCHEME_TYPE.CKKS, 8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    ctx.global_scale = 2**40
    ctx.generate_galois_keys()
    secret = ctx.serialize(save_secret_key=True)
    enc1 = ts.ckks_vector(ctx, col1)
    enc2 = ts.ckks_vector(ctx, col2)
    ctx.make_context_public()
    bundle = {
        "public_context": ctx.serialize(),
        "vectors": {name1: enc1.serialize(), name2: enc2.serialize()},
        "columns": f'["{name1}", "{name2}"]',
        "n": n,
    }
    return bundle, secret


def test_algorithm_registry_non_empty():
    assert len(ALGORITHM_REGISTRY) > 0
    assert "mean" in ALGORITHM_REGISTRY
    assert "descriptive_statistics" in ALGORITHM_REGISTRY
    assert "correlation" in ALGORITHM_REGISTRY


def test_run_computation_unknown_algorithm():
    from app.services.he_service import run_computation
    with pytest.raises(ValueError, match="Unknown algorithm"):
        run_computation({}, "invalid_algorithm")


def test_load_bundle_rejects_pickle():
    with pytest.raises(BundleError, match="Pickle"):
        load_bundle(b"\x80\x04dummy")


def test_dump_bundle_rejects_secret_context():
    with pytest.raises(BundleError, match="secret_context"):
        dump_bundle({
            "public_context": b"pub",
            "secret_context": b"sec",
            "vectors": {"x": b"ct"},
            "columns": ["x"],
            "n": 1,
        })


@pytest.mark.skipif(not TENSEAL_AVAILABLE, reason="tenseal not installed")
def test_encrypt_decrypt_roundtrip():
    ctx = ts.context(ts.SCHEME_TYPE.CKKS, 8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    ctx.global_scale = 2**40
    ctx.generate_galois_keys()
    plain = [1.0, 2.0, 3.0, 4.0, 5.0]
    enc = ts.ckks_vector(ctx, plain)
    dec = enc.decrypt()
    for i, (p, d) in enumerate(zip(plain, dec)):
        assert abs(p - d) < 0.01, f"Index {i}: expected {p}, got {d}"


@pytest.mark.skipif(not TENSEAL_AVAILABLE, reason="tenseal not installed")
def test_mean_computation():
    from algorithms import finalize_encrypted_result
    from app.services.he_service import run_computation

    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    expected_mean = sum(values) / len(values)
    bundle, secret = _make_simple_bundle(values)
    enc_result = run_computation(bundle, "mean", ["col1"])
    assert enc_result.get("encrypted") is True
    assert "mean" not in enc_result
    result = finalize_encrypted_result(secret, enc_result)
    assert abs(result["mean"] - expected_mean) < 0.5


@pytest.mark.skipif(not TENSEAL_AVAILABLE, reason="tenseal not installed")
def test_correlation_computation():
    from algorithms import finalize_encrypted_result
    from app.services.he_service import run_computation

    a = [1.0, 2.0, 3.0, 4.0, 5.0]
    b = [2.0, 4.0, 5.0, 4.0, 6.0]
    bundle, secret = _make_two_column_bundle(a, b)
    enc_result = run_computation(bundle, "correlation", ["a", "b"])
    assert enc_result.get("encrypted") is True
    result = finalize_encrypted_result(secret, enc_result)
    expected = np.corrcoef(a, b)[0, 1]
    assert abs(result["correlation"] - expected) < 0.1


@pytest.mark.skipif(not TENSEAL_AVAILABLE, reason="tenseal not installed")
def test_ciphertext_size_reasonable():
    bundle, _secret = _make_simple_bundle([1.0, 2.0, 3.0] * 10)
    raw = bundle["vectors"]["col1"]
    assert len(raw) < 10 * 1024 * 1024, "Ciphertext should be under 10 MB for small vector"
