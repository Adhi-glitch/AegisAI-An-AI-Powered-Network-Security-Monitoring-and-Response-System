from agents.detection.port_scan import (
    PORT_SCAN_RULE_SOURCE,
    PORT_SCAN_THRESHOLD,
    PortScanDetector,
)


def test_port_scan_emits_low_severity_signal_at_distinct_syn_threshold():
    detector = PortScanDetector()

    for destination_port in range(1, PORT_SCAN_THRESHOLD):
        assert detector.observe_syn(
            "192.0.2.10", "198.51.100.20", destination_port, 0x02, 10.0
        ) is None

    event = detector.observe_syn(
        "192.0.2.10", "198.51.100.20", PORT_SCAN_THRESHOLD, 0x02, 10.1
    )

    assert event == {
        "source_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "protocol": 6,
        "predicted": "Port Scan",
        "confidence": None,
        "severity": "low",
        "detection_source": PORT_SCAN_RULE_SOURCE,
        "distinct_destination_ports": PORT_SCAN_THRESHOLD,
        "window_seconds": 60.0,
    }


def test_repeated_ports_and_syn_ack_packets_do_not_count_toward_threshold():
    detector = PortScanDetector()

    for _ in range(30):
        assert detector.observe_syn("192.0.2.10", "198.51.100.20", 80, 0x02, 1.0) is None
    for destination_port in range(1, PORT_SCAN_THRESHOLD + 1):
        assert detector.observe_syn(
            "192.0.2.10", "198.51.100.20", destination_port, 0x12, 1.1
        ) is None
    for destination_port in range(100, 100 + PORT_SCAN_THRESHOLD - 2):
        assert detector.observe_syn(
            "192.0.2.10", "198.51.100.20", destination_port, 0x02, 1.2
        ) is None


def test_ports_expire_outside_the_rolling_window():
    detector = PortScanDetector()
    for destination_port in range(1, PORT_SCAN_THRESHOLD):
        detector.observe_syn(
            "192.0.2.10", "198.51.100.20", destination_port, 0x02, 1.0
        )

    assert detector.observe_syn(
        "192.0.2.10", "198.51.100.20", 20, 0x02, 61.001
    ) is None

    event = None
    for destination_port in range(PORT_SCAN_THRESHOLD + 1, (2 * PORT_SCAN_THRESHOLD)):
        event = detector.observe_syn(
            "192.0.2.10",
            "198.51.100.20",
            destination_port,
            0x02,
            61.01,
        )

    assert event is not None
    assert event["distinct_destination_ports"] == PORT_SCAN_THRESHOLD


def test_port_scan_signals_are_suppressed_during_cooldown():
    detector = PortScanDetector()

    def scan_at(timestamp):
        events = []
        for destination_port in range(1, PORT_SCAN_THRESHOLD + 1):
            event = detector.observe_syn(
                "192.0.2.10",
                "198.51.100.20",
                destination_port,
                0x02,
                timestamp,
            )
            if event is not None:
                events.append(event)
        return events

    assert len(scan_at(10.0)) == 1
    assert scan_at(11.0) == []
    assert len(scan_at(71.0)) == 1
