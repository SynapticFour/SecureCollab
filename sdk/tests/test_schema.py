# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest

from securecollab.exceptions import SchemaError
from securecollab.schema import analyze_csv_columns


def test_analyze_missing_file():
    with pytest.raises(SchemaError):
        analyze_csv_columns("/nonexistent.csv")


def test_analyze_numeric_csv(tmp_path: Path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("x,y\n1.0,2.0\n3.0,4.0\n", encoding="utf-8")
    result = analyze_csv_columns(str(csv_path))
    assert result["row_count"] == 2
    names = {c["name"] for c in result["columns"]}
    assert names == {"x", "y"}
    by_name = {c["name"]: c for c in result["columns"]}
    assert by_name["x"]["range"] == [1.0, 3.0]
