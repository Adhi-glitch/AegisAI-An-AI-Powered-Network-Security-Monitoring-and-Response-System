import pytest
from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

import network_capture
from network_capture import _resolve_interface, get_capture_status, get_interfaces, start_capture, stop_capture


class FakeSniffer:
    def __init__(self, **kwargs):
        self.callback = kwargs["prn"]
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def test_capture_interface_names_are_sniffer_resolvable():
    devices = list(conf.ifaces.values())
    assert get_interfaces() == sorted({str(device.name) for device in devices})
    for device in devices:
        name = str(device.name)
        assert _resolve_interface(name) == name
        network_name = getattr(device, "network_name", None)
        if network_name:
            assert _resolve_interface(str(network_name)) == name


def test_capture_controller_emits_flows_and_flushes_on_stop(monkeypatch):
    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr("network_capture._new_sniffer", make_sniffer)
    monkeypatch.setattr("network_capture._resolve_interface", lambda interface: interface)
    flows = []
    status = start_capture(flows.append, interface="test0", idle_timeout=1.0)

    assert status["status"] == "running"
    assert status["interface"] == "test0"
    packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=12000, dport=80) / Raw(load=b"a")
    packet.time = 1.0
    sniffer_holder["sniffer"].callback(packet)
    assert get_capture_status()["packet_count"] == 1

    status = stop_capture()

    assert status["status"] == "stopped"
    assert status["flow_count"] == 1
    assert len(flows) == 1
    assert flows[0]["total_packets"] == 1


def test_capture_status_reports_async_sniffer_failure(monkeypatch):
    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr("network_capture._new_sniffer", make_sniffer)
    start_capture(lambda _flow: None)
    sniffer_holder["sniffer"].running = False
    sniffer_holder["sniffer"].exception = RuntimeError("pcap provider unavailable")

    status = get_capture_status()

    assert status["status"] == "error"
    assert status["last_error"] == "pcap provider unavailable"
    stop_capture()


def test_packet_processing_failure_is_reported_without_killing_capture(monkeypatch):
    class BrokenTracker:
        dropped_flows = 0

        def __init__(self, **_kwargs):
            pass

        def add_packet(self, _packet):
            raise ValueError("malformed packet")

        def flush(self):
            return []

    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr("network_capture.FlowTracker", BrokenTracker)
    monkeypatch.setattr("network_capture._new_sniffer", make_sniffer)
    monkeypatch.setattr("network_capture._resolve_interface", lambda interface: interface)
    start_capture(lambda _flow: None, interface="test0")

    packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=12000, dport=80)
    sniffer_holder["sniffer"].callback(packet)
    status = get_capture_status()

    assert status["status"] == "running"
    assert status["packet_count"] == 1
    assert status["callback_errors"] == 1
    assert "malformed packet" in status["last_error"]
    assert stop_capture()["status"] == "stopped"


def test_tracker_initialization_failure_resets_capture_state(monkeypatch):
    def broken_tracker(**_kwargs):
        raise ValueError("invalid tracker configuration")

    monkeypatch.setattr("network_capture.FlowTracker", broken_tracker)
    monkeypatch.setattr("network_capture._resolve_interface", lambda interface: interface)

    with pytest.raises(RuntimeError, match="invalid tracker configuration"):
        start_capture(lambda _flow: None, interface="test0")

    status = get_capture_status()
    assert status["status"] == "error"
    assert "invalid tracker configuration" in status["last_error"]


def test_failed_capture_stop_is_not_reported_as_stopped(monkeypatch):
    class StuckSniffer(FakeSniffer):
        def stop(self):
            raise RuntimeError("sniffer did not stop")

    def make_sniffer(**kwargs):
        return StuckSniffer(**kwargs)

    monkeypatch.setattr("network_capture._new_sniffer", make_sniffer)
    monkeypatch.setattr("network_capture._resolve_interface", lambda interface: interface)
    start_capture(lambda _flow: None, interface="test0")

    status = stop_capture()

    assert status["status"] == "error"
    assert "sniffer did not stop" in status["last_error"]
    assert get_capture_status()["status"] == "error"
    network_capture._SNIFFER.running = False
    assert stop_capture()["status"] == "stopped"