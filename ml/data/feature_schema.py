"""
Feature schema for CICIDS2017 flow features.
This is a representative subset and should be extended to the
full CICFlowMeter feature set when you ingest the real CSVs.

Schema: feature_name -> dtype
"""
from typing import Dict

FEATURE_SCHEMA = {
    "Flow Duration": "int64",
    "Total Fwd Packets": "int64",
    "Total Backward Packets": "int64",
    "Total Length of Fwd Packets": "int64",
    "Total Length of Bwd Packets": "int64",
    "Fwd Packet Length Max": "int64",
    "Fwd Packet Length Min": "int64",
    "Bwd Packet Length Max": "int64",
    "Bwd Packet Length Min": "int64",
    "Fwd IAT Mean": "float64",
    "Bwd IAT Mean": "float64",
    "Label": "category",
}


def get_feature_list():
    return list(FEATURE_SCHEMA.keys())
