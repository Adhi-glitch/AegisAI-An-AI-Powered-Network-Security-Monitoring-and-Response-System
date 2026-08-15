"""
CSV-based feature extractor: converts a CSV row into a feature dict
compatible with the trained model column order.
"""
from __future__ import annotations

from typing import Any, Dict

import numpy as np
import pandas as pd


def extract_from_row(row) -> Dict[str, Any]:
    """Accept Series or dict; keep numeric fields; preserve common metadata keys."""
    if isinstance(row, pd.Series):
        data = row.to_dict()
    elif isinstance(row, dict):
        data = row
    else:
        try:
            data = pd.Series(row).to_dict()
        except Exception:
            return {}

    out: Dict[str, Any] = {}
    for k, v in data.items():
        key = str(k).strip()
        if key.lower() in ("label", "attack", "attack_cat"):
            continue
        if key in ("source_ip", "dest_ip", "protocol", "Source IP", "Destination IP"):
            # normalize metadata names
            if "source" in key.lower():
                out["source_ip"] = v
            elif "dest" in key.lower():
                out["dest_ip"] = v
            else:
                out["protocol"] = v
            continue
        if isinstance(v, (int, float, np.integer, np.floating)) and not (isinstance(v, float) and (np.isnan(v) or np.isinf(v))):
            out[key] = float(v)
        else:
            try:
                fv = float(v)
                if np.isfinite(fv):
                    out[key] = fv
            except (TypeError, ValueError):
                continue
    return out
