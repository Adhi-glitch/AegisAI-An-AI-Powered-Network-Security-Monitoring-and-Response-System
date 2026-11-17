import os
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app import app
from database import models
from database.init_db import SessionLocal


def _admin_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": os.environ["AEGIS_ADMIN_USERNAME"],
            "password": os.environ["AEGIS_ADMIN_PASSWORD"],
        },
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_feed_import_validates_ip_and_updates_duplicate_entries():
    source = f"test-{uuid4().hex[:12]}"
    item = {
        "ip": "203.0.113.123",
        "threat_type": "Port Scan",
        "source": source,
        "severity": "medium",
        "abuse_score": 20,
    }

    with TestClient(app) as client:
        headers = _admin_headers(client)
        first = client.post("/api/v1/threat-intel/import", json=[item], headers=headers)
        updated = client.post(
            "/api/v1/threat-intel/import",
            json=[{**item, "severity": "high", "abuse_score": 80}],
            headers=headers,
        )
        invalid = client.post(
            "/api/v1/threat-intel/import",
            json=[{**item, "ip": "not-an-ip"}],
            headers=headers,
        )
        lookup = client.get(
            "/api/v1/threat-intel/203.0.113.123",
            headers=headers,
        )

    assert first.status_code == 200
    assert first.json() == {"imported": 1, "created": 1, "updated": 0}
    assert updated.status_code == 200
    assert updated.json() == {"imported": 1, "created": 0, "updated": 1}
    assert invalid.status_code == 422
    assert lookup.status_code == 200
    assert lookup.json()["known_bad"] is True
    assert len(lookup.json()["items"]) == 1
    assert lookup.json()["items"][0]["severity"] == "high"

    db = SessionLocal()
    try:
        row = (
            db.query(models.ThreatFeed)
            .filter(
                models.ThreatFeed.ip == item["ip"],
                models.ThreatFeed.source == source,
            )
            .one()
        )
        assert row.abuse_score == 80
    finally:
        db.close()
