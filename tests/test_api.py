import os

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.app import app
from backend.auth import get_current_admin, get_current_user
from backend.routers import alerts as alerts_router
from backend.routers import stats as stats_router
from agents.coordinator.coordinator import ModelUnavailableError


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
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "Security overview" in res.text
    assert 'id="detection-class-chips"' in res.text
    assert "/static/dashboard.js" in res.text
    assert "/static/dashboard.css" in res.text


def test_homepage_is_public_and_links_to_signin(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "Network signals" in response.text
    assert 'href="/signin"' in response.text
    assert '<div id="root"></div>' not in response.text


def test_dashboard_does_not_depend_on_frontend_build(client, monkeypatch, tmp_path):
    monkeypatch.setattr("backend.app.FRONTEND_INDEX", tmp_path / "missing-index.html")

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Security overview" in response.text


def test_compiled_console_remains_available_at_console_route(client):
    response = client.get("/console")
    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text


def test_signin_and_dashboard_routes_serve_their_pages(client):
    res = client.get("/signin")
    dashboard = client.get("/dashboard")
    legacy = client.get("/legacy")
    assert res.status_code == dashboard.status_code == legacy.status_code == 200
    assert 'id="signin-form"' in res.text
    assert "Security overview" in dashboard.text
    assert 'id="capture-start"' in legacy.text


def test_product_and_dashboard_assets_are_served(client):
    for asset in ("site.css", "site.js", "signin.js", "dashboard.css", "dashboard.js", "dashboard-ui.js"):
        response = client.get(f"/static/{asset}")
        assert response.status_code == 200, asset
        assert response.content, asset
    favicon = client.get("/favicon.svg")
    assert favicon.status_code == 200
    assert "<svg" in favicon.text


def test_dashboard_explains_dry_run(client):
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "no firewall change is made" in res.text.lower()


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/v1/alerts",
        "/api/v1/detections",
        "/api/v1/actions",
        "/alerts",
        "/detections",
        "/actions",
    ],
)
@pytest.mark.parametrize("limit", ["0", "-1", "201"])
def test_paginated_endpoints_reject_invalid_limits(client, endpoint, limit):
    previous = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "test-viewer",
        "role": "viewer",
        "is_active": True,
    }
    try:
        response = client.get(endpoint, params={"limit": limit})
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = previous

    assert response.status_code == 422


def test_health_endpoint_stays_live_when_model_bundle_is_invalid(client, monkeypatch):
    def unavailable():
        raise ValueError("invalid bundle")

    monkeypatch.setattr(stats_router, "load_runtime", unavailable)

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["model_loaded"] is False
    assert "model_error" in response.json()


def test_alert_ingest_returns_service_unavailable_when_inference_fails(client, monkeypatch):
    def unavailable(_features):
        raise ModelUnavailableError("The active model is unavailable.")

    previous = app.dependency_overrides.get(get_current_admin)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "test-admin",
        "role": "admin",
        "is_active": True,
    }
    monkeypatch.setattr(alerts_router, "process_features", unavailable)
    try:
        response = client.post(
            "/api/v1/alerts",
            json={"source_ip": "192.0.2.1", "dest_ip": "198.51.100.1"},
        )
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_current_admin, None)
        else:
            app.dependency_overrides[get_current_admin] = previous

    assert response.status_code == 503
    assert "model is unavailable" in response.json()["detail"]


def test_stats_endpoint(client):
    login = client.post(
        "/api/v1/auth/token",
        data={"username": "viewer", "password": os.getenv("AEGIS_VIEWER_PASSWORD", "viewer2024")},
    )
    token = login.json()["access_token"]
    res = client.get("/stats", headers={"Authorization": f"Bearer {token}"})
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
    assert res.status_code == 401
    login = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")},
    )
    assert login.status_code == 200
    res = client.post(
        "/alerts",
        json=payload,
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["recorded"] is False
    assert body["id"] is None


def test_viewer_can_read_capture_status_but_cannot_run_commands(client):
    login = client.post(
        "/api/v1/auth/token",
        data={"username": "viewer", "password": os.getenv("AEGIS_VIEWER_PASSWORD", "viewer2024")},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get("/api/v1/capture/status", headers=headers).status_code == 200
    assert client.get("/api/v1/alerts", headers=headers).status_code == 200
    assert client.get("/api/v1/detections", headers=headers).status_code == 200
    assert client.get("/api/v1/actions", headers=headers).status_code == 200
    export = client.get("/api/v1/detections/export.csv", headers=headers)
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    assert "detection_id,alert_id,timestamp,threat,severity" in export.text
    assert client.get("/api/v1/capture/interfaces", headers=headers).status_code == 403
    assert client.post("/api/v1/capture/start", json={}, headers=headers).status_code == 403
    assert client.post(
        "/api/v1/alerts",
        json={"source_ip": "192.0.2.1", "raw_features": {}},
        headers=headers,
    ).status_code == 403
    assert client.post(
        "/detect",
        json={"features": {"Flow Duration": 1}},
        headers=headers,
    ).status_code == 403
    assert client.post("/actions/unblock", json={"ip": "192.0.2.1"}, headers=headers).status_code == 403


def test_threat_data_and_websocket_require_authentication(client):
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.get("/api/v1/detections").status_code == 401
    assert client.get("/api/v1/actions").status_code == 401
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/ws/feed"):
            pass
    assert error.value.code == 4401


def test_admin_cannot_use_viewer_only_report_export(client):
    login = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")},
    )
    response = client.get(
        "/api/v1/detections/export.csv",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 403
