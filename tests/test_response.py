import os

from fastapi.testclient import TestClient

from agents.response.adapters import MockFirewallAdapter
from agents.response.policy_engine import evaluate_policy
from agents.response.response_engine import ResponseEngine
from backend.app import app
from backend.routers import response as response_router


def test_response_decision():
    engine = ResponseEngine(dry_run=True)
    action = engine.decide_action(0.85)
    assert action in ("block", "rate_limit", "log")
    res = engine.apply_action("198.51.100.5", action)
    assert "status" in res


def test_policy_uses_attack_and_severity_context():
    decision = evaluate_policy(attack_type="DDoS", confidence=0.95, severity="high")
    assert decision.action == "block"
    assert decision.rule_id == "high-confidence-volume-attack"
    assert decision.requires_approval is False


def test_policy_protects_critical_assets_and_supports_approval():
    decision = evaluate_policy(
        attack_type="Web Attack",
        confidence=0.95,
        severity="critical",
        asset_criticality="critical",
        mode="approval-required",
    )
    assert decision.action == "quarantine"
    assert decision.requires_approval is True


def test_policy_rejects_unknown_mode():
    try:
        evaluate_policy(confidence=0.9, mode="unsafe")
    except ValueError as exc:
        assert "mode" in str(exc)
    else:
        raise AssertionError("invalid policy mode was accepted")


def test_policy_preview_request_validates_confidence():
    from backend.routers.response import PolicyPreviewRequest

    request = PolicyPreviewRequest(confidence=0.9, attack_type="Port Scan")
    assert request.mode == "dry-run"


def test_response_adapter_allowlist_and_audit():
    adapter = MockFirewallAdapter()
    engine = ResponseEngine(dry_run=True, adapter=adapter, allowlist={"203.0.113.10"})
    assert engine.apply_action("203.0.113.10", "block")["status"] == "whitelisted"
    result = engine.apply_action("203.0.113.11", "block")
    assert result["status"] == "dry_run_blocked"
    assert adapter.operations == [{"operation": "block", "ip": "203.0.113.11"}]
    assert len(engine.audit_log) == 2


def test_response_action_rate_limit():
    engine = ResponseEngine(dry_run=True, max_actions_per_minute=1)
    assert engine.apply_action("203.0.113.20", "log")["status"] == "logged"
    assert engine.apply_action("203.0.113.21", "log")["status"] == "action_rate_limited"


def test_response_engine_keeps_its_in_memory_audit_bounded():
    engine = ResponseEngine(max_actions_per_minute=10, max_audit_records=3)

    for index in range(5):
        engine.apply_action(f"203.0.113.{index + 1}", "log")

    assert len(engine.audit_log) == 3
    assert [entry["ip"] for entry in engine.audit_log] == [
        "203.0.113.3",
        "203.0.113.4",
        "203.0.113.5",
    ]


def test_response_approval_requires_admin_and_executes_only_after_approval(monkeypatch):
    adapter = MockFirewallAdapter()
    test_engine = ResponseEngine(dry_run=True, adapter=adapter)
    monkeypatch.setattr(response_router, "engine", test_engine)

    with TestClient(app) as client:
        viewer_login = client.post(
            "/api/v1/auth/token",
            data={
                "username": os.environ["AEGIS_VIEWER_USERNAME"],
                "password": os.environ["AEGIS_VIEWER_PASSWORD"],
            },
        )
        admin_login = client.post(
            "/api/v1/auth/token",
            data={
                "username": os.environ["AEGIS_ADMIN_USERNAME"],
                "password": os.environ["AEGIS_ADMIN_PASSWORD"],
            },
        )
        viewer_headers = {
            "Authorization": f"Bearer {viewer_login.json()['access_token']}"
        }
        admin_headers = {
            "Authorization": f"Bearer {admin_login.json()['access_token']}"
        }
        pending = client.post(
            "/api/v1/response/execute",
            json={
                "ip": "203.0.113.222",
                "action": "block",
                "mode": "approval-required",
            },
            headers=viewer_headers,
        )
        direct_execution = client.post(
            "/api/v1/response/execute",
            json={"ip": "203.0.113.223", "action": "block", "mode": "dry-run"},
            headers=viewer_headers,
        )
        viewer_live_execution = client.post(
            "/api/v1/response/execute",
            json={"ip": "203.0.113.225", "action": "block", "mode": "auto-live"},
            headers=viewer_headers,
        )
        live_execution = client.post(
            "/api/v1/response/execute",
            json={"ip": "203.0.113.224", "action": "block", "mode": "auto-live"},
            headers=admin_headers,
        )
        viewer_approvals = client.get(
            "/api/v1/response/approvals",
            headers=viewer_headers,
        )
        decision = client.post(
            f"/api/v1/response/approvals/{pending.json()['approval_id']}/decision",
            params={"approved": "true", "reason": "Test approval"},
            headers=admin_headers,
        )
        audit = client.get("/api/v1/response/audit", headers=admin_headers)

    assert pending.status_code == 200
    assert pending.json()["status"] == "pending_approval"
    assert direct_execution.status_code == 403
    assert viewer_live_execution.status_code == 403
    assert live_execution.status_code == 409
    assert viewer_approvals.status_code == 403
    assert decision.status_code == 200
    assert decision.json()["status"] == "approved"
    assert decision.json()["action_status"] == "dry_run_blocked"
    assert decision.json()["adapter"]["executed"] is False
    assert adapter.operations == [{"operation": "block", "ip": "203.0.113.222"}]
    assert {item["status"] for item in audit.json()["items"]} >= {"pending", "approved"}
