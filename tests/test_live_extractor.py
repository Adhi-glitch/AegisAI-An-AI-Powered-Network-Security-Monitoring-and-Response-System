from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from agents.feature_extraction.live_extractor import FlowTracker
from ml.data.multidataset import LIVE_FEATURE_COLUMNS


def test_flow_tracker_emits_bidirectional_model_feature_vector():
    tracker = FlowTracker(idle_timeout=1.0)
    forward = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=42000, dport=443) / Raw(load=b"abc")
    reverse = IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=443, dport=42000) / Raw(load=b"xy")
    forward.time = 10.0
    reverse.time = 10.5

    assert tracker.add_packet(forward) == []
    assert tracker.add_packet(reverse) == []

    next_flow = IP(src="192.0.2.30", dst="198.51.100.40") / TCP(sport=43000, dport=80) / Raw(load=b"z")
    next_flow.time = 12.0
    completed = tracker.add_packet(next_flow)

    assert len(completed) == 1
    flow = completed[0]
    assert list(column for column in LIVE_FEATURE_COLUMNS if column in flow) == LIVE_FEATURE_COLUMNS
    assert flow["src_packets"] == 1
    assert flow["dst_packets"] == 1
    assert flow["src_bytes"] == len(forward)
    assert flow["dst_bytes"] == len(reverse)
    assert flow["protocol"] == 6
    assert flow["src_port"] == 42000
    assert flow["dst_port"] == 443


def test_flow_tracker_flushes_pending_flows_and_ignores_non_ip_packets():
    tracker = FlowTracker()
    packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1, dport=2)
    packet.time = 1.0

    tracker.add_packet(packet)
    assert tracker.add_packet(Raw(load=b"not an IP packet")) == []
    assert tracker.unsupported_packets == 1

    flushed = tracker.flush()

    assert len(flushed) == 1
    assert tracker.pending_flows == 0


def test_flow_tracker_rejects_nonfinite_timestamps():
    tracker = FlowTracker()
    packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=12000, dport=80)
    packet.time = float("nan")

    assert tracker.add_packet(packet) == []
    assert tracker.pending_flows == 0
    assert tracker.unsupported_packets == 1


def test_flow_tracker_caps_pending_flows_and_expiry_heap():
    tracker = FlowTracker(idle_timeout=120.0, max_duration=120.0, max_pending_flows=1)
    first = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=12000, dport=80)
    second = IP(src="192.0.2.3", dst="198.51.100.4") / TCP(sport=12001, dport=80)
    first.time = 1.0
    second.time = 2.0

    tracker.add_packet(first)
    tracker.add_packet(second)

    assert tracker.pending_flows == 1
    assert tracker.dropped_flows == 1

    for index in range(500):
        first.time = 3.0 + index / 100
        tracker.add_packet(first)

    assert len(tracker._expiry_heap) <= 64


def test_flow_tracker_enriches_flows_with_observed_dns_name():
    tracker = FlowTracker()
    answer = (
        IP(src="192.0.2.53", dst="192.0.2.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=17,
            qr=1,
            ancount=1,
            qd=DNSQR(qname="updates.example.test"),
            an=DNSRR(
                rrname="updates.example.test",
                type="A",
                rdata="198.51.100.20",
                ttl=60,
            ),
        )
    )
    answer.time = 10.0
    tracker.add_packet(answer)

    site_flow = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=42000, dport=443)
    site_flow.time = 11.0
    tracker.add_packet(site_flow)

    site = next(flow for flow in tracker.flush() if flow["dest_ip"] == "198.51.100.20")
    assert site["site_name"] == "updates.example.test"
    assert site["dest_ip"] == "198.51.100.20"