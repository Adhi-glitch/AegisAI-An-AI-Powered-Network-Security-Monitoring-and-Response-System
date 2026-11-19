"""Run a deterministic, packet-free AegisAI demonstration scenario.

The default mode completes immediately while representing five minutes of
activity. Use --realtime only when a paced presentation is desired.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.reporting import generate_incident_report
from agents.reporting.incident_correlation import correlate_incidents
from agents.response.response_engine import ResponseEngine


def build_events() -> list[dict]:
    start = datetime.now()
    scenarios = [("Port Scan", 0), ("Brute Force", 90), ("Botnet", 210)]
    return [
        {"timestamp": (start + timedelta(seconds=offset)).isoformat(), "source_ip": "198.51.100.42", "dest_ip": "10.0.0.8", "attack_type": attack, "severity": "high"}
        for attack, offset in scenarios
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realtime", action="store_true", help="pace the three scenario stages")
    args = parser.parse_args()
    engine = ResponseEngine(dry_run=True)
    events = build_events()
    decisions = [engine.evaluate_policy(confidence=0.93, attack_type=event["attack_type"], severity=event["severity"]) for event in events]
    incidents = correlate_incidents(events)
    report = generate_incident_report(incidents[0], "json") if incidents else {}
    if args.realtime:
        for _ in events:
            time.sleep(1)
    print(json.dumps({"duration_seconds": 300, "simulated": True, "events": events, "decisions": [decision.__dict__ for decision in decisions], "incidents": incidents, "report": report}, indent=2, default=str))


if __name__ == "__main__":
    main()