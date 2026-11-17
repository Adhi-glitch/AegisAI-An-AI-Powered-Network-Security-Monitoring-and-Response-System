import os

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app import app
from agents.detection.inference import infer
from ml.models.bundle import load_bundle
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
PROTOTYPE_TEST = ROOT / "ml" / "data" / "splits" / "prototype" / "test.csv"

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def bundle():
    return load_bundle()

@pytest.fixture
def example(bundle):
    frame = pd.read_csv(PROTOTYPE_TEST)
    benign_id = bundle.label_classes.index("Benign")
    for _, row in frame.loc[frame["label"] != benign_id].iterrows():
        features = {column: float(row[column]) for column in bundle.feature_columns}
        predicted, _ = infer(bundle.model, features, bundle_dir=bundle.directory)
        expected_id = int(row["label"])
        if predicted == bundle.label_classes[expected_id]:
            return {"expected_label": expected_id, "features": features}
    raise AssertionError("The prototype test split has no correctly classified threat example")

@pytest.fixture
def label_classes(bundle):
    return bundle.label_classes

def test_api_integration_full(client, example, label_classes):
    # 1. Login as admin
    login_res = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    
    # 2. Ingest alert with run_detection=True
    expected_name = label_classes[example["expected_label"]]
    
    payload = {
        "source_ip": "10.10.10.10",
        "dest_ip": "192.168.1.5",
        "protocol": "TCP",
        "raw_features": example["features"],
        "run_detection": True
    }
    
    ingest_res = client.post(
        "/api/v1/alerts",
        json=payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert ingest_res.status_code == 200
    data = ingest_res.json()
    assert "detection_id" in data
    
    result = data.get("result", {})
    assert result.get("predicted") == expected_name, f"Expected {expected_name}, got {result.get('predicted')}"
    
    detection_id = data["detection_id"]
    
    # 3. Verify detection is persisted correctly
    det_res = client.get(
        f"/api/v1/detections/{detection_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert det_res.status_code == 200
    det_data = det_res.json()
    assert det_data["predicted_class"] == expected_name

    actions_res = client.get(
        "/api/v1/actions?limit=200",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert actions_res.status_code == 200
    recorded_action = next(
        action for action in actions_res.json()["items"]
        if action["detection_id"] == detection_id
    )
    assert recorded_action["action_type"] == result["response"]["status"]
