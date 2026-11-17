from agents.analytics.features import network_graph, posture_digest, psi, simulate_scenario
from agents.reporting import generate_pdf_report
from agents.reporting.incident_correlation import merge_incidents, split_incident, update_incident_status


def test_incident_workflow_and_technique_mapping():
    incident = {"incident_id": "INC-1", "events": [{"timestamp": "now"}], "timeline": ["now"], "status": "open"}
    assert update_incident_status(incident, "contained")["status"] == "contained"
    assert len(split_incident(incident)) == 1
    assert merge_incidents([incident])["status"] == "investigating"


def test_feature_metrics_are_deterministic():
    assert psi([1, 2, 3], [1, 2, 3]) == 0
    result = simulate_scenario(["Port Scan", "Brute Force", "Botnet"], speed=2)
    assert result["detection_rate"] == 1.0
    assert result["response_latency_seconds"] == 0.5
    assert len(network_graph([{"source_ip": "a", "dest_ip": "b"}])["nodes"]) == 2
    assert posture_digest(attack_volume=2, blocked=2, unresolved_incidents=0, model_health=1)["score"] == 100


def test_pdf_report_has_pdf_signature():
    assert generate_pdf_report({"events": [], "attack_type": "Port Scan"}).startswith(b"%PDF")