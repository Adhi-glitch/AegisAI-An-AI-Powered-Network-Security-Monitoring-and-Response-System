import pandas as pd
from agents.feature_extraction.csv_extractor import extract_from_row


def test_csv_extractor_basic():
    row = pd.Series({"a": 1, "b": 2.5, "c": "x"})
    out = extract_from_row(row)
    assert isinstance(out, dict)
    assert "a" in out and "b" in out
