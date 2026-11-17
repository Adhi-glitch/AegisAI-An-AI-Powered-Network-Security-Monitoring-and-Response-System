from agents.reporting import generate_incident_report
from agents.reporting.incident_correlation import correlate_incidents


def test_correlates_related_events_and_maps_kill_chain():
    incidents = correlate_incidents([
        {"timestamp": "2026-10-26T10:00:00", "source_ip": "198.51.100.1", "dest_ip": "10.0.0.2", "attack_type": "Port Scan", "severity": "high"},
        {"timestamp": "2026-10-26T10:01:00", "source_ip": "198.51.100.1", "dest_ip": "10.0.0.2", "attack_type": "Port Scan", "severity": "high"},
    ])
    assert len(incidents) == 1
    assert incidents[0]["kill_chain_stage"] == "discovery"
    assert len(incidents[0]["timeline"]) == 2


def test_report_has_executive_and_technical_sections():
    incident = {"source_ip": "198.51.100.1", "dest_ip": "10.0.0.2", "attack_type": "Botnet", "severity": "high", "kill_chain_stage": "command-and-control", "events": [{}]}
    report = generate_incident_report(incident, "markdown")
    assert "Executive Summary" in report
    assert "Technical Appendix" in report