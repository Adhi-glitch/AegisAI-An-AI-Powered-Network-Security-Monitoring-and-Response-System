from scapy.layers.inet import IP, TCP
from scapy.layers.inet import UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from agents.detection.live_rules import (
    AUTH_ATTEMPT_RULE_SOURCE,
    AUTH_ATTEMPT_THRESHOLD,
    BOTNET_IOC_RULE_SOURCE,
    DDOS_RATE_RULE_SOURCE,
    DDOS_SOURCE_THRESHOLD,
    DDOS_SYN_THRESHOLD,
    DOS_RATE_RULE_SOURCE,
    DOS_SYN_THRESHOLD,
    WEB_SIGNATURE_RULE_SOURCE,
    LiveRuleDetector,
)
from agents.feature_extraction.live_extractor import FlowTracker


def _syn_packet(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    timestamp,
    flags="S",
):
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / TCP(sport=source_port, dport=destination_port, flags=flags)
    )
    packet.time = timestamp
    return packet


def test_single_source_syn_rate_emits_dos_indicator_without_confidence():
    detector = LiveRuleDetector()
    events = []

    for index in range(DOS_SYN_THRESHOLD):
        packet = _syn_packet(
            "192.0.2.10",
            "198.51.100.20",
            40000 + index,
            80,
            100.0 + index * 0.01,
        )
        events.extend(detector.observe_packet(packet))

    assert len(events) == 1
    assert events[0]["predicted"] == "DoS"
    assert events[0]["detection_source"] == DOS_RATE_RULE_SOURCE
    assert events[0]["confidence"] is None
    assert events[0]["packet_count"] == DOS_SYN_THRESHOLD
    assert events[0]["severity"] == "medium"


def test_dos_rate_requires_initial_syn_packets_within_the_window():
    detector = LiveRuleDetector()

    for index in range(DOS_SYN_THRESHOLD):
        ack = _syn_packet(
            "192.0.2.10",
            "198.51.100.20",
            40500 + index,
            80,
            100.0 + index * 0.001,
            flags="A",
        )
        assert detector.observe_packet(ack) == []

    for index in range(DOS_SYN_THRESHOLD):
        slow_syn = _syn_packet(
            "192.0.2.10",
            "198.51.100.20",
            41000 + index,
            80,
            200.0 + index * 0.03,
        )
        assert detector.observe_packet(slow_syn) == []


def test_multi_source_syn_rate_emits_ddos_indicator():
    detector = LiveRuleDetector()
    events = []
    source_count = DDOS_SOURCE_THRESHOLD
    packets_per_source = DDOS_SYN_THRESHOLD // source_count
    assert packets_per_source < DOS_SYN_THRESHOLD

    for index in range(DDOS_SYN_THRESHOLD):
        source_index = index // packets_per_source
        packet = _syn_packet(
            f"192.0.2.{source_index + 1}",
            "198.51.100.20",
            41000 + index,
            443,
            200.0 + index * 0.001,
        )
        events.extend(detector.observe_packet(packet))

    assert len(events) == 1
    assert events[0]["predicted"] == "DDoS"
    assert events[0]["detection_source"] == DDOS_RATE_RULE_SOURCE
    assert events[0]["confidence"] is None
    assert events[0]["distinct_source_count"] == source_count
    assert events[0]["severity"] == "high"


def test_repeated_auth_service_connections_emit_only_a_pattern_indicator():
    detector = LiveRuleDetector()
    events = []

    for index in range(AUTH_ATTEMPT_THRESHOLD):
        packet = _syn_packet(
            "192.0.2.10",
            "198.51.100.20",
            42000 + index,
            22,
            300.0 + index,
        )
        events.extend(detector.observe_packet(packet))

    assert len(events) == 1
    assert events[0]["predicted"] == "Brute Force"
    assert events[0]["detection_source"] == AUTH_ATTEMPT_RULE_SOURCE
    assert events[0]["confidence"] is None
    assert "cannot confirm login failures" in events[0]["evidence_note"]


def test_retransmitted_syns_from_one_source_port_do_not_inflate_auth_attempts():
    detector = LiveRuleDetector()

    for index in range(AUTH_ATTEMPT_THRESHOLD * 2):
        packet = _syn_packet(
            "192.0.2.10",
            "198.51.100.20",
            42000,
            22,
            350.0 + index,
        )
        assert detector.observe_packet(packet) == []


def test_cleartext_http_signature_emits_web_indicator_without_storing_payload():
    detector = LiveRuleDetector()
    packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=43000, dport=80)
        / Raw(
            load=(
                b"GET /vulnerable.php?id=1%20AND%201%3D1 HTTP/1.1\r\n"
                b"Host: example.test\r\n\r\n"
            )
        )
    )
    packet.time = 400.0

    events = detector.observe_packet(packet)

    assert len(events) == 1
    assert events[0]["predicted"] == "Web Attack"
    assert events[0]["detection_source"] == WEB_SIGNATURE_RULE_SOURCE
    assert events[0]["confidence"] is None
    assert events[0]["indicator"] == "sql_boolean_tautology"
    assert "payload" not in events[0]
    assert "encrypted HTTPS" in events[0]["evidence_note"]


def test_benign_http_and_encrypted_https_payload_do_not_match_cleartext_rules():
    detector = LiveRuleDetector()
    benign = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=43000, dport=80)
        / Raw(load=b"GET /?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
    )
    encrypted = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=43001, dport=443)
        / Raw(load=b"\x16\x03\x01\x00\x2e")
    )
    benign.time = 500.0
    encrypted.time = 501.0

    assert detector.observe_packet(benign) == []
    assert detector.observe_packet(encrypted) == []


def test_flow_tracker_emits_packet_rate_indicator_from_live_packet_path():
    tracker = FlowTracker(idle_timeout=30.0)
    events = []

    for index in range(DOS_SYN_THRESHOLD):
        events.extend(
            tracker.add_packet(
                _syn_packet(
                    "192.0.2.10",
                    "198.51.100.20",
                    44000 + index,
                    80,
                    600.0 + index * 0.01,
                )
            )
        )

    assert any(
        event.get("detection_source") == DOS_RATE_RULE_SOURCE
        for event in events
    )


def test_configured_botnet_domain_ioc_emits_high_severity_indicator(tmp_path):
    ioc_file = tmp_path / "threat_iocs.json"
    ioc_file.write_text(
        '{"domains": ["c2.example.test"], "ips": ["203.0.113.66"]}',
        encoding="utf-8",
    )
    detector = LiveRuleDetector(ioc_file)
    packet = (
        IP(src="192.0.2.10", dst="192.0.2.1")
        / UDP(sport=53000, dport=53)
        / DNS(qd=DNSQR(qname="node.c2.example.test"))
    )
    packet.time = 700.0

    events = detector.observe_packet(packet)

    assert len(events) == 1
    assert events[0]["predicted"] == "Botnet"
    assert events[0]["detection_source"] == BOTNET_IOC_RULE_SOURCE
    assert events[0]["ioc_type"] == "domain"
    assert events[0]["ioc_value"] == "c2.example.test"
    assert events[0]["protocol"] == 17
    assert events[0]["severity"] == "high"
    assert events[0]["confidence"] is None


def test_configured_botnet_ip_ioc_matches_live_tcp_destination(tmp_path):
    ioc_file = tmp_path / "threat_iocs.json"
    ioc_file.write_text(
        '{"domains": [], "ips": ["203.0.113.66"]}',
        encoding="utf-8",
    )
    detector = LiveRuleDetector(ioc_file)
    packet = _syn_packet(
        "192.0.2.10",
        "203.0.113.66",
        45000,
        443,
        800.0,
    )

    events = detector.observe_packet(packet)

    assert len(events) == 1
    assert events[0]["detection_source"] == BOTNET_IOC_RULE_SOURCE
    assert events[0]["ioc_type"] == "ip"
    assert events[0]["ioc_value"] == "203.0.113.66"


def test_configured_botnet_ioc_matches_are_rate_limited(tmp_path):
    ioc_file = tmp_path / "threat_iocs.json"
    ioc_file.write_text(
        '{"domains": [], "ips": ["203.0.113.66"]}',
        encoding="utf-8",
    )
    detector = LiveRuleDetector(ioc_file)
    packet = _syn_packet(
        "192.0.2.10",
        "203.0.113.66",
        45000,
        443,
        900.0,
    )

    assert len(detector.observe_packet(packet)) == 1
    packet.time = 901.0
    assert detector.observe_packet(packet) == []
