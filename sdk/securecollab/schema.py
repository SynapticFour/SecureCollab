# SPDX-License-Identifier: Apache-2.0
"""Schema analysis and negotiation with study protocol."""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from typing import Any

from .exceptions import SchemaError
from .http import api_get, api_post


def analyze_csv_columns(csv_path: str) -> dict[str, Any]:
    path = Path(csv_path)
    if not path.exists():
        raise SchemaError("Datei nicht gefunden")
    cols: dict[str, list[float]] = defaultdict(list)
    nulls: dict[str, int] = defaultdict(int)
    keys: list[str] | None = None
    n = 0
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            n += 1
            if keys is None:
                keys = list(row.keys())
            for k in keys:
                val = row.get(k, "")
                if val is None or val == "" or (isinstance(val, str) and val.strip() == ""):
                    nulls[k] += 1
                    continue
                try:
                    cols[k].append(float(val))
                except (ValueError, TypeError):
                    pass
    if not keys or n == 0:
        raise SchemaError("Keine Zeilen")
    columns_out = []
    for key in keys:
        values = cols.get(key, [])
        data_type = "float"
        sample_range = None
        if values:
            if all(v == int(v) for v in values):
                data_type = "integer"
            sample_range = [min(values), max(values)]
        columns_out.append({
            "name": key,
            "type": data_type,
            "range": sample_range,
            "null_pct": round(100.0 * nulls[key] / n, 2) if n else 0,
            "sample_values_count": len(values),
        })
    return {"columns": columns_out, "row_count": n}


def negotiate_schema(
    csv_path: str,
    study_id: str,
    institution_email: str,
    api_base_url: str,
    proposed_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    analysis = analyze_csv_columns(csv_path)
    local_columns = {c["name"]: c for c in analysis.get("columns", [])}
    protocol = api_get(api_base_url, f"/studies/{study_id}/protocol", email=institution_email)
    if not isinstance(protocol, dict):
        raise SchemaError("Ungültiges Protocol")
    required = protocol.get("required_columns") or protocol.get("column_definitions") or []
    if not required:
        return {
            "compatible": False,
            "issues": ["Kein required_columns im Protocol"],
            "approved_mappings": [],
            "warnings": [],
        }
    if proposed_mapping is None:
        proposed_mapping = {}
        for col_def in required:
            name = col_def.get("name", "") if isinstance(col_def, dict) else ""
            aliases = col_def.get("aliases") or [] if isinstance(col_def, dict) else []
            for local_name in local_columns:
                if local_name == name or local_name in aliases:
                    proposed_mapping[local_name] = name
                    break
    local_schema = {
        "columns": [
            {
                "name": c["name"],
                "type": c["type"],
                "sample_range": c.get("range"),
                "null_percentage": c.get("null_pct", 0),
            }
            for c in local_columns.values()
        ]
    }
    return api_post(
        api_base_url,
        f"/studies/{study_id}/schema/submit",
        data={
            "institution_email": institution_email,
            "local_schema": local_schema,
            "proposed_mapping": proposed_mapping,
        },
        email=institution_email,
    )
