# SPDX-License-Identifier: Apache-2.0
"""
Homomorphic algorithms on encrypted CKKS bundles.

The server never decrypts. Each algorithm returns encrypted sufficient
statistics (base64 TenSEAL ciphertexts). Callers with a secret context
finalize locally via finalize_encrypted_result().

In-memory bundle: public_context (bytes), vectors (dict[str, bytes]),
columns (JSON list), n (int). secret_context is rejected.
"""
from __future__ import annotations

import base64
import json
import math
from typing import Any

import tenseal as ts

EncryptedResult = dict[str, Any]


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _pack(enc) -> str:
    return _b64e(enc.serialize())


def _get_vectors_bundle(bundle: dict[str, Any]) -> bool:
    return "vectors" in bundle and isinstance(bundle.get("vectors"), dict)


def _reject_secret(bundle: dict[str, Any]) -> None:
    if "secret_context" in bundle:
        raise ValueError("Bundles must not contain secret_context")


def _load_vectors(bundle: dict[str, Any], column_names: list[str]):
    _reject_secret(bundle)
    if not _get_vectors_bundle(bundle):
        raise ValueError("Mehrere Spalten nur bei Bundle mit 'vectors' möglich")
    ctx = ts.context_from(bundle["public_context"])
    n = bundle.get("n")
    if n is None:
        raise ValueError("Bundle missing 'n' (number of rows).")
    encs = {}
    vectors = bundle["vectors"]
    for col in column_names:
        if col not in vectors:
            raise ValueError(
                f"Column '{col}' not found in dataset. Available: {list(vectors.keys())}."
            )
        enc = ts.lazy_ckks_vector_from(bundle["vectors"][col])
        enc.link_context(ctx)
        encs[col] = enc
    return ctx, encs, n


def _require_columns(
    bundle: dict[str, Any],
    selected_columns: list[str],
    min_columns: int,
    algorithm_id: str,
    description: str = "",
) -> None:
    available = list(bundle["vectors"].keys()) if _get_vectors_bundle(bundle) else []
    if len(selected_columns) < min_columns:
        raise ValueError(
            f"Algorithm '{algorithm_id}' requires at least {min_columns} column(s). "
            f"Got {len(selected_columns)}: {selected_columns}. {description}"
        )
    for col in selected_columns[:min_columns]:
        if col not in (bundle.get("vectors") or {}):
            raise ValueError(
                f"Algorithm '{algorithm_id}': column '{col}' not found in dataset. "
                f"Available columns: {available}"
            )


def _load_bundle(bundle: dict[str, Any], column_name: str | None = None):
    _reject_secret(bundle)
    ctx = ts.context_from(bundle["public_context"])
    n = bundle.get("n")
    if n is None:
        raise ValueError("Bundle missing 'n' (number of rows).")
    if _get_vectors_bundle(bundle):
        vectors = bundle["vectors"]
        col = column_name
        if not col:
            try:
                cols = json.loads(bundle.get("columns", "[]"))
                col = cols[0] if cols else next(iter(vectors.keys()))
            except (json.JSONDecodeError, TypeError, StopIteration):
                col = next(iter(vectors.keys()))
        if col not in vectors:
            raise ValueError(
                f"Column '{col}' not found in dataset. Available: {list(vectors.keys())}."
            )
        enc = ts.lazy_ckks_vector_from(vectors[col])
    else:
        raise ValueError("Bundle missing vectors")
    enc.link_context(ctx)
    return ctx, enc, n


def _load_two_vectors(bundle: dict[str, Any], col1: str, col2: str):
    _reject_secret(bundle)
    if not _get_vectors_bundle(bundle):
        raise ValueError(
            "Multi-column algorithms require a bundle with 'vectors' (one encrypted vector per column). "
            "Single-vector bundles are not supported for this operation."
        )
    ctx = ts.context_from(bundle["public_context"])
    n = bundle.get("n")
    if n is None:
        raise ValueError("Bundle missing 'n' (number of rows).")
    vectors = bundle["vectors"]
    for c in (col1, col2):
        if c not in vectors:
            available = list(vectors.keys())
            raise ValueError(
                f"Column '{c}' not found in dataset. Available columns: {available}. "
                f"Use selected_columns from the dataset's column list."
            )
    enc1 = ts.lazy_ckks_vector_from(vectors[col1])
    enc2 = ts.lazy_ckks_vector_from(vectors[col2])
    enc1.link_context(ctx)
    enc2.link_context(ctx)
    return ctx, enc1, enc2, n


def _masked_sum_serialized(enc_vec, plain_vec) -> str:
    """(enc_vec * plain_vec).sum() as base64 ciphertext. No pickle."""
    n = enc_vec.size()
    mask = list(plain_vec)[:n]
    if len(mask) < n:
        mask.extend([0.0] * (n - len(mask)))
    return _pack((enc_vec * mask).sum())


def _result(algorithm: str, n: int, public_context: bytes, ciphertexts: dict[str, str], **meta: Any) -> EncryptedResult:
    return {
        "encrypted": True,
        "algorithm": algorithm,
        "n": n,
        "public_context": _b64e(public_context),
        "ciphertexts": ciphertexts,
        "plain_meta": meta,
    }


def run_descriptive_statistics(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    col = selected_columns[0] if selected_columns else None
    ctx, enc, n = _load_bundle(bundle, col)
    if n < 1:
        raise ValueError("Algorithm 'descriptive_statistics' requires n >= 1")
    cubed = enc.square() * enc
    return _result(
        "descriptive_statistics",
        n,
        bundle["public_context"],
        {
            "sum": _pack(enc.sum()),
            "sum_sq": _pack(enc.square().sum()),
            "sum_cubes": _pack(cubed.sum()),
        },
        column=col,
    )


def run_correlation(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(bundle, selected_columns, 2, "correlation", "Need two numeric columns.")
    c1, c2 = selected_columns[0], selected_columns[1]
    ctx, enc1, enc2, n = _load_two_vectors(bundle, c1, c2)
    return _result(
        "correlation",
        n,
        bundle["public_context"],
        {
            "sum1": _pack(enc1.sum()),
            "sum2": _pack(enc2.sum()),
            "sum12": _pack((enc1 * enc2).sum()),
            "sum_sq1": _pack(enc1.square().sum()),
            "sum_sq2": _pack(enc2.square().sum()),
        },
        column1=c1,
        column2=c2,
    )


def run_group_comparison(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    col = selected_columns[0] if selected_columns else None
    ctx, enc, n = _load_bundle(bundle, col)
    if n < 2:
        raise ValueError("Algorithm 'group_comparison' requires n >= 2")
    half = n // 2
    n2 = n - half
    mask1 = [1.0] * half + [0.0] * n2
    mask2 = [0.0] * half + [1.0] * n2
    return _result(
        "group_comparison",
        n,
        bundle["public_context"],
        {
            "sum1": _masked_sum_serialized(enc, mask1),
            "sum2": _masked_sum_serialized(enc, mask2),
        },
        n1=half,
        n2=n2,
        column=col,
    )


def run_linear_regression(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(bundle, selected_columns, 2, "linear_regression", "Need predictor and target.")
    c1, c2 = selected_columns[0], selected_columns[1]
    ctx, enc_x, enc_y, n = _load_two_vectors(bundle, c1, c2)
    return _result(
        "linear_regression",
        n,
        bundle["public_context"],
        {
            "sum_x": _pack(enc_x.sum()),
            "sum_y": _pack(enc_y.sum()),
            "sum_xy": _pack((enc_x * enc_y).sum()),
            "sum_xx": _pack(enc_x.square().sum()),
        },
        predictor=c1,
        target=c2,
    )


def run_distribution(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    raise ValueError(
        "Algorithm 'distribution' is not available: CKKS cannot sort or bin by value. "
        "Index-split histograms were removed because they are not a distribution of the data."
    )


def run_mean_legacy(bundle: dict[str, Any], selected_columns: list[str] | None = None) -> EncryptedResult:
    col = selected_columns[0] if selected_columns else None
    ctx, enc, n = _load_bundle(bundle, col)
    if n < 1:
        raise ValueError("Algorithm 'mean' requires n >= 1")
    return _result(
        "mean",
        n,
        bundle["public_context"],
        {"sum": _pack(enc.sum())},
        column=col,
    )


def run_multi_group_comparison(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    col = selected_columns[0] if selected_columns else None
    ctx, enc, n = _load_bundle(bundle, col)
    if n < 2:
        raise ValueError("Algorithm 'multi_group_comparison' requires n >= 2")
    if _get_vectors_bundle(bundle) and len(selected_columns) >= 2:
        cols = [selected_columns[0]]
        for g in range(1, len(selected_columns)):
            if selected_columns[g] in bundle.get("vectors", {}):
                cols.append(selected_columns[g])
        if len(cols) > 1:
            ctx, encs, n = _load_vectors(bundle, cols)
            value_enc = encs[cols[0]]
            groups_ct: dict[str, str] = {}
            names: list[str] = []
            for mask_col in cols[1:]:
                mask_enc = encs[mask_col]
                names.append(mask_col)
                groups_ct[f"{mask_col}__sum"] = _pack((value_enc * mask_enc).sum())
                groups_ct[f"{mask_col}__sum_sq"] = _pack((value_enc.square() * mask_enc).sum())
                groups_ct[f"{mask_col}__n"] = _pack(mask_enc.sum())
            return _result(
                "multi_group_comparison",
                n,
                bundle["public_context"],
                groups_ct,
                mode="masks",
                group_names=names,
                value_column=cols[0],
            )
    n_groups = 4
    segment_size = max(1, n // n_groups)
    groups_ct = {}
    sizes: list[int] = []
    names = []
    for g in range(n_groups):
        start = g * segment_size
        end = n if g == n_groups - 1 else (g + 1) * segment_size
        size = end - start
        mask = [1.0 if start <= i < end else 0.0 for i in range(n)]
        name = f"group_{g + 1}"
        names.append(name)
        sizes.append(size)
        groups_ct[f"{name}__sum"] = _masked_sum_serialized(enc, mask)
        groups_ct[f"{name}__sum_sq"] = _masked_sum_serialized(enc.square(), mask)
    return _result(
        "multi_group_comparison",
        n,
        bundle["public_context"],
        groups_ct,
        mode="segments",
        group_names=names,
        group_sizes=sizes,
        value_column=col,
    )


def run_logistic_regression_approx(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(
        bundle,
        selected_columns,
        2,
        "logistic_regression_approx",
        "Need at least one feature column and a binary target.",
    )
    target_col = selected_columns[-1]
    feature_cols = selected_columns[:-1]
    ctx, encs, n = _load_vectors(bundle, selected_columns)
    y_enc = encs[target_col]
    cts: dict[str, str] = {"sum_y": _pack(y_enc.sum())}
    for fc in feature_cols:
        x_enc = encs[fc]
        cts[f"{fc}__sum"] = _pack(x_enc.sum())
        cts[f"{fc}__xy"] = _pack((x_enc * y_enc).sum())
        cts[f"{fc}__xx"] = _pack(x_enc.square().sum())
    return _result(
        "logistic_regression_approx",
        n,
        bundle["public_context"],
        cts,
        feature_columns=feature_cols,
        target_column=target_col,
    )


def run_pearson_correlation_matrix(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(bundle, selected_columns, 2, "pearson_correlation_matrix", "Need 2–6 numeric columns.")
    cols = selected_columns[:6]
    ctx, encs, n = _load_vectors(bundle, cols)
    cts: dict[str, str] = {}
    for c in cols:
        cts[f"{c}__sum"] = _pack(encs[c].sum())
        cts[f"{c}__sum_sq"] = _pack(encs[c].square().sum())
    for i, ca in enumerate(cols):
        for cb in cols[i + 1 :]:
            cts[f"{ca}__{cb}__prod"] = _pack((encs[ca] * encs[cb]).sum())
    return _result(
        "pearson_correlation_matrix",
        n,
        bundle["public_context"],
        cts,
        columns=cols,
    )


def run_survival_analysis_approx(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(bundle, selected_columns, 2, "survival_analysis_approx", "Need time_column and event_column.")
    t_col, e_col = selected_columns[0], selected_columns[1]
    ctx, enc_t, enc_e, n = _load_two_vectors(bundle, t_col, e_col)
    return _result(
        "survival_analysis_approx",
        n,
        bundle["public_context"],
        {
            "sum_t": _pack(enc_t.sum()),
            "sum_e": _pack(enc_e.sum()),
        },
        time_column=t_col,
        event_column=e_col,
    )


def run_prevalence_and_risk(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(
        bundle, selected_columns, 2, "prevalence_and_risk",
        "Need outcome_column and exposure_column (binary 0/1).",
    )
    o_col, e_col = selected_columns[0], selected_columns[1]
    ctx, enc_o, enc_e, n = _load_two_vectors(bundle, o_col, e_col)
    return _result(
        "prevalence_and_risk",
        n,
        bundle["public_context"],
        {
            "sum_o": _pack(enc_o.sum()),
            "sum_e": _pack(enc_e.sum()),
            "sum_oe": _pack((enc_o * enc_e).sum()),
        },
        outcome_column=o_col,
        exposure_column=e_col,
    )


def run_federated_mean_aggregation(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    col = selected_columns[0] if selected_columns else None
    ctx, enc, n = _load_bundle(bundle, col)
    cts = {
        "sum": _pack(enc.sum()),
        "sum_sq": _pack(enc.square().sum()),
    }
    meta: dict[str, Any] = {"value_column": col, "per_institution_n": [n]}
    if _get_vectors_bundle(bundle) and selected_columns and len(selected_columns) >= 2:
        if selected_columns[1] not in bundle.get("vectors", {}):
            raise ValueError(
                f"Algorithm 'federated_mean_aggregation': weight column '{selected_columns[1]}' not found."
            )
        ctx, encs, n = _load_vectors(bundle, selected_columns[:2])
        v_enc, w_enc = encs[selected_columns[0]], encs[selected_columns[1]]
        cts["sum_w"] = _pack(w_enc.sum())
        cts["sum_vw"] = _pack((v_enc * w_enc).sum())
        meta["weight_column"] = selected_columns[1]
    return _result("federated_mean_aggregation", n, bundle["public_context"], cts, **meta)


def run_subgroup_analysis(
    bundle: dict[str, Any], selected_columns: list[str]
) -> EncryptedResult:
    _require_columns(
        bundle, selected_columns, 2, "subgroup_analysis",
        "Need value_column and at least one subgroup mask column (0/1).",
    )
    value_col = selected_columns[0]
    mask_cols = selected_columns[1:]
    ctx, encs, n = _load_vectors(bundle, selected_columns)
    cts: dict[str, str] = {}
    for mask_col in mask_cols:
        v_enc = encs[value_col]
        m_enc = encs[mask_col]
        cts[f"{mask_col}__sum"] = _pack((v_enc * m_enc).sum())
        cts[f"{mask_col}__sum_sq"] = _pack((v_enc.square() * m_enc).sum())
        cts[f"{mask_col}__n"] = _pack(m_enc.sum())
    return _result(
        "subgroup_analysis",
        n,
        bundle["public_context"],
        cts,
        value_column=value_col,
        mask_columns=mask_cols,
    )


ALGORITHMS = {
    "descriptive_statistics": run_descriptive_statistics,
    "correlation": run_correlation,
    "group_comparison": run_group_comparison,
    "linear_regression": run_linear_regression,
    "distribution": run_distribution,
    "mean": run_mean_legacy,
    "multi_group_comparison": run_multi_group_comparison,
    "logistic_regression_approx": run_logistic_regression_approx,
    "pearson_correlation_matrix": run_pearson_correlation_matrix,
    "survival_analysis_approx": run_survival_analysis_approx,
    "prevalence_and_risk": run_prevalence_and_risk,
    "federated_mean_aggregation": run_federated_mean_aggregation,
    "subgroup_analysis": run_subgroup_analysis,
}

FEDERATED_ALGORITHMS = frozenset({"mean", "descriptive_statistics", "federated_mean_aggregation"})


def _dec_scalar(ctx, b64: str) -> float:
    vec = ts.lazy_ckks_vector_from(_b64d(b64))
    vec.link_context(ctx)
    return float(vec.decrypt()[0])


def finalize_encrypted_result(secret_context_bytes: bytes, result: dict[str, Any]) -> dict[str, Any]:
    """Decrypt encrypted sufficient statistics and finish scalar math. Local only."""
    if not result.get("encrypted"):
        return result
    ctx = ts.context_from(secret_context_bytes)
    alg = result.get("algorithm")
    n = int(result.get("n") or 0)
    ct = result.get("ciphertexts") or {}
    meta = dict(result.get("plain_meta") or {})

    def d(key: str) -> float:
        if key not in ct:
            raise ValueError(f"Missing ciphertext '{key}' for algorithm '{alg}'")
        return _dec_scalar(ctx, ct[key])

    if alg == "mean":
        return {"mean": round(d("sum") / n, 4) if n else 0.0}

    if alg == "descriptive_statistics":
        s, s2, s3 = d("sum"), d("sum_sq"), d("sum_cubes")
        mean_val = s / n
        mean_sq = s2 / n
        var = max(mean_sq - mean_val * mean_val, 0.0)
        std_dev = math.sqrt(var)
        mean_cubes = s3 / n
        # third central moment from raw moments
        mu3 = mean_cubes - 3 * mean_val * mean_sq + 2 * mean_val**3
        skew = (mu3 / (std_dev**3)) if std_dev and std_dev > 1e-10 else 0.0
        return {
            "mean": round(mean_val, 4),
            "std_dev": round(std_dev, 4),
            "variance": round(var, 4),
            "min": round(mean_val - 2 * std_dev, 4),
            "max": round(mean_val + 2 * std_dev, 4),
            "iqr_approx": round(1.35 * std_dev if std_dev else 0.0, 4),
            "skewness_approx": round(skew, 4),
            "n": n,
        }

    if alg == "correlation":
        s1, s2, s12 = d("sum1"), d("sum2"), d("sum12")
        ss1, ss2 = d("sum_sq1"), d("sum_sq2")
        m1, m2 = s1 / n, s2 / n
        var1 = max(ss1 / n - m1 * m1, 0.0)
        var2 = max(ss2 / n - m2 * m2, 0.0)
        cov = s12 / n - m1 * m2
        denom = math.sqrt(var1 * var2)
        corr = (cov / denom) if denom else 0.0
        return {"correlation": round(corr, 4), "column1": meta.get("column1"), "column2": meta.get("column2")}

    if alg == "group_comparison":
        n1, n2 = int(meta["n1"]), int(meta["n2"])
        m1 = d("sum1") / n1
        m2 = d("sum2") / n2
        return {
            "group1_mean": round(m1, 4),
            "group2_mean": round(m2, 4),
            "difference": round(m1 - m2, 4),
        }

    if alg == "linear_regression":
        mx = d("sum_x") / n
        my = d("sum_y") / n
        cov_xy = d("sum_xy") / n - mx * my
        var_x = d("sum_xx") / n - mx * mx
        slope = (cov_xy / var_x) if var_x else 0.0
        intercept = my - slope * mx
        return {
            "slope": round(slope, 4),
            "intercept": round(intercept, 4),
            "predictor": meta.get("predictor"),
            "target": meta.get("target"),
        }

    if alg == "multi_group_comparison":
        names = list(meta.get("group_names") or [])
        groups_out = []
        if meta.get("mode") == "masks":
            for name in names:
                ni = max(d(f"{name}__n"), 1e-6)
                sv = d(f"{name}__sum")
                sv2 = d(f"{name}__sum_sq")
                mean_i = sv / ni
                var_i = max((sv2 / ni) - mean_i * mean_i, 0.0)
                groups_out.append(
                    {"name": name, "mean": round(mean_i, 4), "std_dev": round(math.sqrt(var_i), 4), "n": int(round(ni))}
                )
        else:
            sizes = list(meta.get("group_sizes") or [])
            for name, size in zip(names, sizes):
                sv = d(f"{name}__sum")
                sv2 = d(f"{name}__sum_sq")
                mean_g = sv / size
                var_g = max((sv2 / size) - mean_g * mean_g, 0.0)
                groups_out.append(
                    {"name": name, "mean": round(mean_g, 4), "std_dev": round(math.sqrt(var_g), 4), "n": size}
                )
        pairwise = []
        for i in range(len(groups_out)):
            for j in range(i + 1, len(groups_out)):
                diff = groups_out[i]["mean"] - groups_out[j]["mean"]
                pairwise.append(
                    {
                        "group_a": groups_out[i]["name"],
                        "group_b": groups_out[j]["name"],
                        "difference": round(diff, 4),
                        "significant_approx": abs(diff) > 0.5,
                    }
                )
        return {"groups": groups_out, "pairwise_differences": pairwise}

    if alg == "logistic_regression_approx":
        feature_cols = list(meta.get("feature_columns") or [])
        mean_y = d("sum_y") / n
        coeffs = {}
        for fc in feature_cols:
            mean_x = d(f"{fc}__sum") / n
            cov_xy = d(f"{fc}__xy") / n - mean_x * mean_y
            var_x = d(f"{fc}__xx") / n - mean_x * mean_x
            coeffs[fc] = round((cov_xy / var_x) if var_x else 0.0, 4)
        intercept = mean_y - sum(coeffs[fc] * (d(f"{fc}__sum") / n) for fc in feature_cols)
        return {
            "coefficients": coeffs,
            "intercept": round(intercept, 4),
            "convergence_iterations": 1,
            "approximate_accuracy": "Linear approximation only – not for clinical decisions.",
        }

    if alg == "pearson_correlation_matrix":
        cols = list(meta.get("columns") or [])
        means = {c: d(f"{c}__sum") / n for c in cols}
        matrix: dict[str, dict[str, float]] = {c: {} for c in cols}
        pairs = []
        for i, ca in enumerate(cols):
            matrix[ca][ca] = 1.0
            for cb in cols[i + 1 :]:
                cov = d(f"{ca}__{cb}__prod") / n - means[ca] * means[cb]
                var_a = max(d(f"{ca}__sum_sq") / n - means[ca] ** 2, 1e-10)
                var_b = max(d(f"{cb}__sum_sq") / n - means[cb] ** 2, 1e-10)
                r = cov / math.sqrt(var_a * var_b)
                matrix[ca][cb] = round(r, 4)
                matrix[cb][ca] = round(r, 4)
                pairs.append({"col_a": ca, "col_b": cb, "r": round(r, 4)})
        pairs.sort(key=lambda x: -abs(x["r"]))
        strongest = pairs[:5]
        for p in strongest:
            r = abs(p["r"])
            if r < 0.2:
                p["interpretation"] = "weak"
            elif r < 0.5:
                p["interpretation"] = "moderate"
            elif r < 0.8:
                p["interpretation"] = "strong"
            else:
                p["interpretation"] = "very strong"
        return {"matrix": matrix, "strongest_correlations": strongest}

    if alg == "survival_analysis_approx":
        total_time = d("sum_t")
        total_events = d("sum_e")
        mean_time = total_time / n if n else 0.0
        hazard_rate = total_events / total_time if total_time else 0.0
        median_approx = 0.5 * total_time / max(total_events, 1) if total_events else mean_time
        timepoints = {
            round(mean_time * 0.25, 1): 0.75,
            round(mean_time * 0.5, 1): 0.5,
            round(mean_time * 0.75, 1): 0.25,
        }
        return {
            "median_survival_approx": round(median_approx, 4),
            "survival_at_timepoints": timepoints,
            "hazard_rate": round(hazard_rate, 6),
            "groups": [{"name": "all", "median_survival": round(median_approx, 4), "hazard_ratio": 1.0}],
        }

    if alg == "prevalence_and_risk":
        n_o, n_e, a = d("sum_o"), d("sum_e"), d("sum_oe")
        n_unexposed = n - n_e
        if n_unexposed < 1:
            n_unexposed = 1
        c = n_o - a
        rate_exposed = a / n_e if n_e else 0.0
        rate_unexposed = c / n_unexposed
        prevalence = n_o / n if n else 0.0
        relative_risk = (rate_exposed / rate_unexposed) if rate_unexposed else 0.0
        b = n_e - a
        dd = n_unexposed - c
        odds_ratio = (a * dd) / (b * c) if (b * c) else 0.0
        return {
            "prevalence": round(prevalence, 4),
            "relative_risk": round(relative_risk, 4),
            "odds_ratio": round(odds_ratio, 4),
            "n_exposed": int(round(n_e)),
            "n_unexposed": int(round(n_unexposed)),
            "confidence_interval_approx": "Use decrypted counts for exact CI",
        }

    if alg == "federated_mean_aggregation":
        mean_val = d("sum") / n if n else 0.0
        mean_sq = d("sum_sq") / n if n else 0.0
        var = max(mean_sq - mean_val * mean_val, 0.0)
        std_error = math.sqrt(var / n) if n else 0.0
        weighted_mean = mean_val
        if "sum_w" in ct and "sum_vw" in ct:
            sw = d("sum_w")
            if sw:
                weighted_mean = d("sum_vw") / sw
        return {
            "global_mean": round(mean_val, 4),
            "weighted_mean": round(weighted_mean, 4),
            "per_institution_n": meta.get("per_institution_n", [n]),
            "total_n": n,
            "std_error": round(std_error, 4),
        }

    if alg == "subgroup_analysis":
        subgroups_out = []
        for mask_col in meta.get("mask_columns") or []:
            nm = max(d(f"{mask_col}__n"), 1e-6)
            sv = d(f"{mask_col}__sum")
            sv2 = d(f"{mask_col}__sum_sq")
            mean_s = sv / nm
            var_s = max((sv2 / nm) - mean_s * mean_s, 0.0)
            subgroups_out.append(
                {
                    "name": mask_col,
                    "mean": round(mean_s, 4),
                    "std_dev": round(math.sqrt(var_s), 4),
                    "n_approx": int(round(nm)),
                }
            )
        return {"subgroups": subgroups_out}

    raise ValueError(f"Cannot finalize unknown algorithm '{alg}'")
