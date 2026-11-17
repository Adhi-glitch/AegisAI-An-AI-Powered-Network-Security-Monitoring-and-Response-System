import os
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app import app
from rag.knowledge_base import KnowledgeBase


def test_ingestion_chunks_and_retrieves_document():
    knowledge = KnowledgeBase([])
    count = knowledge.ingest(
        document_id="local-cve",
        title="Local CVE",
        text="A vulnerable service requires patching immediately.",
        source="local",
        chunk_size=100,
    )
    assert count == 1
    result = knowledge.answer("Which vulnerable service requires patching?")
    assert result["grounded"] is True
    assert result["citations"][0]["document_id"] == "local-cve"


def test_ingestion_replaces_documents_and_counts_only_nonempty_chunks():
    knowledge = KnowledgeBase([])
    count = knowledge.ingest(
        document_id="local-cve",
        title="Local CVE",
        text=f"{'A' * 100}{' ' * 100}{'B' * 100}",
        source="local",
        chunk_size=100,
    )
    assert count == 2
    assert len(knowledge.documents) == 2

    replaced = knowledge.ingest(
        document_id="local-cve",
        title="Updated CVE",
        text="A patched service is available.",
        source="local",
        chunk_size=100,
    )
    assert replaced == 1
    assert len(knowledge.documents) == 1
    assert knowledge.documents[0].title == "Updated CVE"
    assert knowledge.answer("unrelated quantum subject")["grounded"] is False


def test_document_ingestion_is_admin_only_and_query_is_authenticated():
    document_id = f"smoke-{uuid4().hex}"
    document = {
        "document_id": document_id,
        "title": "Telemetry Recovery",
        "text": "Verify telemetry snapshots and backup recovery before incident closure.",
        "source": "local test",
    }

    with TestClient(app) as client:
        admin_login = client.post(
            "/api/v1/auth/token",
            data={
                "username": os.environ["AEGIS_ADMIN_USERNAME"],
                "password": os.environ["AEGIS_ADMIN_PASSWORD"],
            },
        )
        viewer_login = client.post(
            "/api/v1/auth/token",
            data={
                "username": os.environ["AEGIS_VIEWER_USERNAME"],
                "password": os.environ["AEGIS_VIEWER_PASSWORD"],
            },
        )
        admin_headers = {
            "Authorization": f"Bearer {admin_login.json()['access_token']}"
        }
        viewer_headers = {
            "Authorization": f"Bearer {viewer_login.json()['access_token']}"
        }
        denied = client.post(
            "/api/v1/copilot/documents",
            json=document,
            headers=viewer_headers,
        )
        blank = client.post(
            "/api/v1/copilot/documents",
            json={**document, "title": "   "},
            headers=admin_headers,
        )
        ingested = client.post(
            "/api/v1/copilot/documents",
            json=document,
            headers=admin_headers,
        )
        unauthenticated = client.post(
            "/api/v1/copilot/query",
            json={"query": "telemetry backup recovery"},
        )
        grounded = client.post(
            "/api/v1/copilot/query",
            json={"query": "telemetry snapshots backup recovery"},
            headers=viewer_headers,
        )
        weak = client.post(
            "/api/v1/copilot/query",
            json={"query": "quantum neutrino"},
            headers=viewer_headers,
        )

    assert denied.status_code == 403
    assert blank.status_code == 422
    assert ingested.status_code == 200
    assert ingested.json()["chunks_added"] == 1
    assert unauthenticated.status_code == 401
    assert grounded.json()["grounded"] is True
    assert grounded.json()["citations"][0]["document_id"] == document_id
    assert weak.json()["grounded"] is False
    assert weak.json()["citations"] == []