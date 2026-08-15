import pytest
from fastapi.testclient import TestClient

from backend.app import app


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr("backend.app.load_runtime", lambda: {})
    monkeypatch.setattr(
        "backend.app.process_features",
        lambda features: {
            "predicted": "Benign",
            "confidence": 0.99,
            "action": "log",
            "response": {"status": "logged", "ip": features.get("source_ip", "unknown")},
        },
    )
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "model_loaded" in body


def test_dashboard_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "AegisAI" in res.text


def test_stats_endpoint(client):
    res = client.get("/stats")
    assert res.status_code == 200
    body = res.json()
    assert "alerts" in body and "by_class" in body


def test_ingest_alert_without_crashing(client):
    payload = {
        "source_ip": "203.0.113.10",
        "dest_ip": "198.51.100.2",
        "protocol": "TCP",
        "raw_features": {"Flow Duration": 1.0, "Total Fwd Packets": 2.0},
        "run_detection": True,
    }
    res = client.post("/alerts", json=payload)
    assert res.status_code == 200
    body = res.json()
    assert "id" in body
