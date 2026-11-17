import os

from fastapi.testclient import TestClient

from backend.app import app
from database import models
from database.init_db import SessionLocal


def _token(client: TestClient, role: str) -> str:
    username = os.environ[f"AEGIS_{role.upper()}_USERNAME"]
    password = os.environ[f"AEGIS_{role.upper()}_PASSWORD"]
    response = client.post(
        "/api/v1/auth/token",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def _create_alert() -> int:
    db = SessionLocal()
    try:
        alert = models.Alert(source_ip="203.0.113.66", dest_ip="198.51.100.66")
        db.add(alert)
        db.flush()
        db.add(
            models.Detection(
                alert_id=alert.id,
                predicted_class="Port Scan",
                confidence="0.9",
                model_version="test",
            )
        )
        db.commit()
        return alert.id
    finally:
        db.close()


def test_admin_feedback_is_persisted_and_viewer_is_forbidden():
    alert_id = _create_alert()
    with TestClient(app) as client:
        admin_response = client.post(
            f"/api/v1/alerts/{alert_id}/feedback",
            json={"label": "false_positive", "notes": "reviewed sample"},
            headers={"Authorization": f"Bearer {_token(client, 'admin')}"},
        )
        viewer_response = client.post(
            f"/api/v1/alerts/{alert_id}/feedback",
            json={"label": "true_positive"},
            headers={"Authorization": f"Bearer {_token(client, 'viewer')}"},
        )
        missing_response = client.post(
            f"/api/v1/alerts/{alert_id + 99999}/feedback",
            json={"label": "unsure"},
            headers={"Authorization": f"Bearer {_token(client, 'admin')}"},
        )

    assert admin_response.status_code == 200
    assert admin_response.json()["label"] == "false_positive"
    assert viewer_response.status_code == 403
    assert missing_response.status_code == 404

    db = SessionLocal()
    try:
        feedback = (
            db.query(models.AlertFeedback)
            .filter(models.AlertFeedback.alert_id == alert_id)
            .one()
        )
        assert feedback.notes == "reviewed sample"
        assert feedback.analyst == os.environ["AEGIS_ADMIN_USERNAME"]
    finally:
        db.close()
