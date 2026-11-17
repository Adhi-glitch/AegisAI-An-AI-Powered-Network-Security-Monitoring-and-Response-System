import pandas as pd
from fastapi.testclient import TestClient

from agents.detection.threat_policy import PHASE1_THREAT_CLASSES
from backend.app import app
from backend.auth import get_current_admin
from backend.routers import demo as demo_router
from ml.data.multidataset import LABEL_TO_ID


def test_active_model_can_replay_four_held_out_phase_one_classes():
    labels = ["Botnet", "Brute Force", "DDoS", "Web Attack"]
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin",
        "role": "admin",
        "is_active": True,
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/demo/replay", json={"labels": labels})
    finally:
        app.dependency_overrides.pop(get_current_admin, None)

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["persisted"] is False
    assert result["network_packets_sent"] == 0
    assert result["response_actions"] == 0
    assert [item["predicted_class"] for item in result["items"]] == labels
    assert all(item["detection_source"] == "dataset_replay" for item in result["items"])


def test_admin_can_replay_held_out_examples_without_creating_threat_records(
    tmp_path, monkeypatch
):
    labels = ["Botnet", "Brute Force", "DDoS", "Web Attack"]
    dataset = tmp_path / "held-out.csv"
    pd.DataFrame(
        [
            {"label": LABEL_TO_ID[label], "duration": LABEL_TO_ID[label] + 1}
            for label in labels
        ]
    ).to_csv(dataset, index=False)
    monkeypatch.setattr(demo_router, "REPLAY_DATASET", dataset)
    monkeypatch.setattr(
        demo_router,
        "load_runtime",
        lambda: {
            "model": object(),
            "columns": ["duration"],
            "bundle_dir": tmp_path,
            "label_classes": list(PHASE1_THREAT_CLASSES) + ["Benign"],
        },
    )

    def classify_sample(_model, features, bundle_dir):
        class_id = int(features[0]) - 1
        label = next(name for name, value in LABEL_TO_ID.items() if value == class_id)
        return label, 0.91

    monkeypatch.setattr(demo_router, "infer", classify_sample)
    broadcast_events = []

    async def capture_broadcast(event):
        broadcast_events.append(event)

    monkeypatch.setattr(demo_router.ws_manager, "broadcast", capture_broadcast)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin",
        "role": "admin",
        "is_active": True,
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/demo/replay", json={"labels": labels})

        assert response.status_code == 200
        result = response.json()
        assert result["simulated"] is True
        assert result["persisted"] is False
        assert result["network_packets_sent"] == 0
        assert result["response_actions"] == 0
        assert [item["predicted_class"] for item in result["items"]] == labels
        assert all(item["detection_source"] == "dataset_replay" for item in result["items"])
        assert all(item["simulated"] for item in result["items"])
        assert all(item["severity"] == "high" for item in result["items"])
        assert len(broadcast_events) == 4
    finally:
        app.dependency_overrides.pop(get_current_admin, None)


def test_demo_replay_requires_admin_authentication():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/demo/replay",
            json={"labels": ["Botnet"]},
        )

    assert response.status_code == 401


def test_demo_replay_rejects_duplicate_labels(tmp_path, monkeypatch):
    dataset = tmp_path / "held-out.csv"
    pd.DataFrame([{"label": LABEL_TO_ID["Botnet"], "duration": 1}]).to_csv(
        dataset, index=False
    )
    monkeypatch.setattr(demo_router, "REPLAY_DATASET", dataset)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin",
        "role": "admin",
        "is_active": True,
    }
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/demo/replay",
                json={"labels": ["Botnet", "Botnet"]},
            )
    finally:
        app.dependency_overrides.pop(get_current_admin, None)

    assert response.status_code == 422
