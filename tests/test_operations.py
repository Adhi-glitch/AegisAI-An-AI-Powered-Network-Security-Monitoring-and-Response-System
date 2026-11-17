import os

from fastapi.testclient import TestClient

from backend.app import app
from backend.routers.operations import parse_alert_query


def test_natural_language_alert_query_becomes_safe_filters():
    filters = parse_alert_query("show brute force attempts from the last 2 hours with confidence above 0.9")
    assert filters["attack_type"] == "Brute Force"
    assert filters["min_confidence"] == 0.9
    assert "since" in filters


def test_unknown_alert_query_does_not_create_sql_fragments():
    assert parse_alert_query("show everything; drop table alerts") == {}


def test_model_health_reports_the_loaded_bundle_and_marks_overlap():
    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/token",
            data={
                "username": os.environ["AEGIS_ADMIN_USERNAME"],
                "password": os.environ["AEGIS_ADMIN_PASSWORD"],
            },
        )
        token = login.json()["access_token"]
        response = client.get(
            "/api/v1/model-health",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    result = response.json()
    assert result["active_model"] == "multi_dataset_bundle"
    assert result["validation_accuracy"] is not None
    assert result["evaluation_status"] == "exploratory"
    assert result["capture_overlap_warning"] is True