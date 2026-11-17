import os
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app import app
from database import models
from database.init_db import SessionLocal


def _token(client: TestClient, username: str, password: str) -> str:
    response = client.post(
        "/api/v1/auth/token",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def _create_incident(events=None, severity="info") -> int:
    db = SessionLocal()
    try:
        incident = models.Incident(
            incident_key=f"test-{uuid4().hex}",
            source_ip="203.0.113.1",
            dest_ip="198.51.100.2",
            attack_type="Port Scan",
            severity=severity,
            status="open",
            events=events or [],
            timeline=[event.get("timestamp") for event in (events or [])],
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.id
    finally:
        db.close()


def test_admin_status_update_persists_and_unknown_incident_returns_404():
    with TestClient(app) as client:
        token = _token(
            client,
            os.environ["AEGIS_ADMIN_USERNAME"],
            os.environ["AEGIS_ADMIN_PASSWORD"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        incident_id = _create_incident()

        updated = client.post(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "investigating"},
            headers=headers,
        )
        missing = client.post(
            "/api/v1/incidents/999999/status",
            json={"status": "closed"},
            headers=headers,
        )

    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"
    assert missing.status_code == 404

    db = SessionLocal()
    try:
        assert db.get(models.Incident, incident_id).status == "investigating"
    finally:
        db.close()


def test_viewer_cannot_update_incident_status():
    incident_id = _create_incident()
    with TestClient(app) as client:
        token = _token(
            client,
            os.environ["AEGIS_VIEWER_USERNAME"],
            os.environ["AEGIS_VIEWER_PASSWORD"],
        )
        response = client.post(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "contained"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 403

    db = SessionLocal()
    try:
        assert db.get(models.Incident, incident_id).status == "open"
    finally:
        db.close()


def test_correlate_persists_idempotently_and_all_report_formats_export():
    source_ip = f"198.51.100.{int(uuid4().hex[:2], 16)}"
    events = [
        {
            "timestamp": "2026-11-14T10:00:00",
            "source_ip": source_ip,
            "dest_ip": "203.0.113.200",
            "attack_type": "Port Scan",
            "severity": "high",
        },
        {
            "timestamp": "2026-11-14T10:00:30",
            "source_ip": source_ip,
            "dest_ip": "203.0.113.200",
            "attack_type": "Port Scan",
            "severity": "high",
        },
    ]

    with TestClient(app) as client:
        token = _token(
            client,
            os.environ["AEGIS_VIEWER_USERNAME"],
            os.environ["AEGIS_VIEWER_PASSWORD"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        first = client.post(
            "/api/v1/incidents/correlate",
            json={"events": events},
            headers=headers,
        )
        second = client.post(
            "/api/v1/incidents/correlate",
            json={"events": events},
            headers=headers,
        )
        incident_id = first.json()["items"][0]["incident_id"]
        listed = client.get("/api/v1/incidents", headers=headers)
        persisted_incidents = [
            item
            for item in listed.json()["items"]
            if item["incident_key"].startswith(source_ip)
        ]
        report_payload = {
            "incident": persisted_incidents[0],
            "export_format": "json",
        }
        json_report = client.post(
            "/api/v1/incidents/report",
            json=report_payload,
            headers=headers,
        )
        markdown_report = client.post(
            "/api/v1/incidents/report",
            json={**report_payload, "export_format": "markdown"},
            headers=headers,
        )
        text_report = client.post(
            "/api/v1/incidents/report",
            json={**report_payload, "export_format": "text"},
            headers=headers,
        )
        pdf_report = client.post(
            "/api/v1/incidents/report",
            json={**report_payload, "export_format": "pdf"},
            headers=headers,
        )

    assert first.status_code == second.status_code == 200
    assert first.json()["persisted"] == 1
    assert second.json()["persisted"] == 1
    assert len(persisted_incidents) == 1
    assert incident_id == "INC-0001"
    assert len(persisted_incidents[0]["timeline"]) == 2
    assert len(persisted_incidents[0]["events"]) == 2
    assert "2 related detection event(s)" in json_report.json()["report"]["executive_summary"]
    assert "Executive Summary" in markdown_report.text
    assert text_report.headers["content-type"].startswith("text/plain")
    assert pdf_report.content.startswith(b"%PDF")


def test_admin_merge_and_split_persist_incident_lineage():
    first_events = [
        {"timestamp": "2026-11-14T10:03:00", "source_ip": "203.0.113.1", "dest_ip": "198.51.100.2", "attack_type": "Port Scan", "severity": "medium"},
    ]
    second_events = [
        {"timestamp": "2026-11-14T10:01:00", "source_ip": "203.0.113.1", "dest_ip": "198.51.100.2", "attack_type": "Port Scan", "severity": "high"},
        {"timestamp": "2026-11-14T10:02:00", "source_ip": "203.0.113.1", "dest_ip": "198.51.100.2", "attack_type": "Port Scan", "severity": "high"},
    ]
    first_id = _create_incident(first_events, severity="medium")
    second_id = _create_incident(second_events, severity="high")

    with TestClient(app) as client:
        token = _token(
            client,
            os.environ["AEGIS_ADMIN_USERNAME"],
            os.environ["AEGIS_ADMIN_PASSWORD"],
        )
        headers = {"Authorization": f"Bearer {token}"}
        duplicate = client.post(
            "/api/v1/incidents/merge",
            json={"incident_ids": [first_id, first_id]},
            headers=headers,
        )
        missing = client.post(
            "/api/v1/incidents/merge",
            json={"incident_ids": [first_id, 999999]},
            headers=headers,
        )
        legacy_merge = client.post(
            "/api/v1/incidents/merge",
            json={"events": [{"events": first_events}]},
            headers=headers,
        )
        legacy_split = client.post(
            "/api/v1/incidents/split",
            json={"events": first_events},
            headers=headers,
        )
        merged = client.post(
            "/api/v1/incidents/merge",
            json={"incident_ids": [first_id, second_id]},
            headers=headers,
        )
        split = client.post(
            f"/api/v1/incidents/{first_id}/split",
            headers=headers,
        )
        listed = client.get("/api/v1/incidents", headers=headers)

    assert duplicate.status_code == 422
    assert missing.status_code == 404
    assert legacy_merge.status_code == legacy_split.status_code == 200
    assert len(legacy_split.json()["items"]) == 1
    assert merged.status_code == 200
    assert merged.json()["event_count"] == 3
    assert split.status_code == 200
    assert len(split.json()["items"]) == 3
    incidents = {item["id"]: item for item in listed.json()["items"]}
    assert incidents[first_id]["status"] == "closed"
    assert incidents[second_id]["merged_into_id"] == first_id
    assert incidents[first_id]["severity"] == "high"
    assert incidents[first_id]["timeline"] == [
        "2026-11-14T10:01:00",
        "2026-11-14T10:02:00",
        "2026-11-14T10:03:00",
    ]
    children = [item for item in incidents.values() if item["split_from_id"] == first_id]
    assert len(children) == 3
    assert all(len(item["events"]) == 1 for item in children)


def test_viewer_cannot_merge_or_split_and_single_event_split_is_rejected():
    incident_id = _create_incident([
        {"timestamp": "2026-11-14T10:00:00", "source_ip": "203.0.113.1"},
        {"timestamp": "2026-11-14T10:01:00", "source_ip": "203.0.113.1"},
    ])
    single_event_id = _create_incident([
        {"timestamp": "2026-11-14T10:02:00", "source_ip": "203.0.113.1"},
    ])

    with TestClient(app) as client:
        viewer_token = _token(
            client,
            os.environ["AEGIS_VIEWER_USERNAME"],
            os.environ["AEGIS_VIEWER_PASSWORD"],
        )
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        merge = client.post(
            "/api/v1/incidents/merge",
            json={"incident_ids": [incident_id, single_event_id]},
            headers=viewer_headers,
        )
        split = client.post(
            f"/api/v1/incidents/{incident_id}/split",
            headers=viewer_headers,
        )
        admin_token = _token(
            client,
            os.environ["AEGIS_ADMIN_USERNAME"],
            os.environ["AEGIS_ADMIN_PASSWORD"],
        )
        admin_split = client.post(
            f"/api/v1/incidents/{single_event_id}/split",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert merge.status_code == split.status_code == 403
    assert admin_split.status_code == 409
