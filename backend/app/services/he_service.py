# SPDX-License-Identifier: Apache-2.0
"""Homomorphic encryption operations: run algorithms on encrypted bundles.

Never decrypts. Never loads pickle. secret_context is rejected by the bundle codec.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import tenseal as ts

from algorithms import ALGORITHMS, FEDERATED_ALGORITHMS
from app.services.bundle import load_bundle


def _column_defaults(bundle: dict[str, Any], algorithm: str, selected_columns: list[str]) -> list[str]:
    if selected_columns:
        return selected_columns
    try:
        cols = json.loads(bundle.get("columns", "[]"))
    except (json.JSONDecodeError, TypeError):
        cols = list(bundle.get("vectors", {}).keys())
    if algorithm in ("correlation", "linear_regression", "prevalence_and_risk", "survival_analysis_approx"):
        return cols[:2]
    if algorithm == "pearson_correlation_matrix":
        return cols[: min(6, len(cols))]
    if algorithm in ("logistic_regression_approx", "multi_group_comparison", "subgroup_analysis"):
        return cols[: min(6, len(cols))]
    if algorithm == "federated_mean_aggregation":
        return cols[:2] if len(cols) >= 2 else cols[:1]
    return cols[:1]


def run_computation(
    bundle: dict[str, Any] | str | Path | bytes,
    algorithm: str,
    selected_columns: list[str] | None = None,
    parameters: dict | None = None,
) -> dict[str, Any]:
    """
    Run a registered HE algorithm on an encrypted bundle.
    Returns encrypted sufficient statistics. `parameters` is accepted for the
    job record but unused by current algorithms (reserved).
    """
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}. Allowed: {list(ALGORITHMS.keys())}")
    loaded = load_bundle(bundle)
    cols = _column_defaults(loaded, algorithm, selected_columns or [])
    return ALGORITHMS[algorithm](loaded, cols)


def _add_ciphertexts(public_context: bytes, b64_a: str, b64_b: str) -> str:
    import base64

    ctx = ts.context_from(public_context)
    va = ts.lazy_ckks_vector_from(base64.b64decode(b64_a))
    vb = ts.lazy_ckks_vector_from(base64.b64decode(b64_b))
    va.link_context(ctx)
    vb.link_context(ctx)
    return base64.b64encode((va + vb).serialize()).decode("ascii")


def combine_encrypted_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Homomorphically add encrypted sums from multiple datasets (same study key)."""
    if not results:
        raise ValueError("No results to combine")
    if len(results) == 1:
        return results[0]
    first = results[0]
    import base64

    public_ctx = base64.b64decode(first["public_context"])
    keys = set(first.get("ciphertexts") or {})
    for r in results[1:]:
        keys &= set(r.get("ciphertexts") or {})
    if not keys:
        raise ValueError("Datasets have no overlapping encrypted statistics to combine")
    combined_ct = {}
    for key in keys:
        acc = first["ciphertexts"][key]
        for r in results[1:]:
            acc = _add_ciphertexts(public_ctx, acc, r["ciphertexts"][key])
        combined_ct[key] = acc
    total_n = sum(int(r.get("n") or 0) for r in results)
    meta = dict(first.get("plain_meta") or {})
    meta["per_institution_n"] = [int(r.get("n") or 0) for r in results]
    return {
        "encrypted": True,
        "algorithm": first.get("algorithm"),
        "n": total_n,
        "public_context": first["public_context"],
        "ciphertexts": combined_ct,
        "plain_meta": meta,
    }


def run_on_datasets(
    paths: list[str | Path],
    algorithm: str,
    selected_columns: list[str] | None = None,
    parameters: dict | None = None,
) -> dict[str, Any]:
    """Run an algorithm on one or more on-disk bundles.

    Sum-based algorithms (mean, descriptive_statistics, federated_mean_aggregation)
    combine encrypted aggregates across files. Other algorithms require exactly
    one dataset — they are not silently run on datasets[0].
    """
    if not paths:
        raise ValueError("No dataset files")
    if len(paths) > 1 and algorithm not in FEDERATED_ALGORITHMS:
        raise ValueError(
            f"Algorithm '{algorithm}' cannot combine {len(paths)} datasets. "
            "Use mean, descriptive_statistics, or federated_mean_aggregation for multi-party aggregation."
        )
    parts = [run_computation(p, algorithm, selected_columns, parameters) for p in paths]
    if len(parts) == 1:
        return parts[0]
    return combine_encrypted_results(parts)
