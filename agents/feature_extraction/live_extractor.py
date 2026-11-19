"""Accumulate bidirectional IP packets into the numeric live-model flow schema."""
from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import ipaddress
import math
from itertools import count
from threading import RLock
import time
from typing import Any, Dict

from agents.detection.live_rules import LiveRuleDetector
from agents.detection.port_scan import PortScanDetector

_MAX_PENDING_FLOWS = 50_000


def _packet_parts(packet: Any) -> tuple[tuple[str, int], tuple[str, int], int, int, float] | None:
    if packet is None:
        return None
    try:
        from scapy.layers.inet import IP, TCP, UDP

        if IP not in packet:
            return None
        ip = packet[IP]
        source_port = int(packet[TCP].sport) if TCP in packet else int(packet[UDP].sport) if UDP in packet else 0
        dest_port = int(packet[TCP].dport) if TCP in packet else int(packet[UDP].dport) if UDP in packet else 0
        source = (str(ip.src), source_port)
        destination = (str(ip.dst), dest_port)
        protocol = int(ip.proto)
        packet_bytes = int(len(ip))
        timestamp = float(getattr(packet, "time", time.time()))
        if not math.isfinite(timestamp) or timestamp < 0 or packet_bytes < 0:
            return None
        return source, destination, protocol, packet_bytes, timestamp
    except (ImportError, AttributeError, TypeError, ValueError, OverflowError, OSError):
        return None


def extract_from_packet(packet: Any) -> Dict[str, Any]:
    """Return basic packet identity fields, or an empty dict for unsupported packets."""
    parts = _packet_parts(packet)
    if parts is None:
        return {}
    source, destination, protocol, packet_bytes, timestamp = parts
    return {
        "source_ip": source[0],
        "dest_ip": destination[0],
        "source_port": source[1],
        "dest_port": destination[1],
        "protocol": protocol,
        "packet_bytes": packet_bytes,
        "timestamp": timestamp,
    }


@dataclass
class _Flow:
    source: tuple[str, int]
    destination: tuple[str, int]
    protocol: int
    start: float
    last_seen: float
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0

    def add(self, source: tuple[str, int], packet_bytes: int, timestamp: float) -> None:
        if source == self.source:
            self.forward_packets += 1
            self.forward_bytes += packet_bytes
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_bytes
        self.last_seen = max(self.last_seen, timestamp)

    def to_features(self) -> Dict[str, Any]:
        duration_seconds = max(self.last_seen - self.start, 1e-6)
        total_packets = self.forward_packets + self.backward_packets
        total_bytes = self.forward_bytes + self.backward_bytes
        return {
            "duration": duration_seconds * 1_000_000.0,
            "src_packets": self.forward_packets,
            "dst_packets": self.backward_packets,
            "src_bytes": self.forward_bytes,
            "dst_bytes": self.backward_bytes,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packet_rate": total_packets / duration_seconds,
            "byte_rate": total_bytes / duration_seconds,
            "src_port": self.source[1],
            "dst_port": self.destination[1],
            "protocol": self.protocol,
            "source_ip": self.source[0],
            "dest_ip": self.destination[0],
        }


class FlowTracker:
    """Build simple bidirectional flow features from Scapy-compatible IPv4 packets."""

    def __init__(
        self,
        idle_timeout: float = 2.0,
        max_duration: float = 60.0,
        max_pending_flows: int = _MAX_PENDING_FLOWS,
    ) -> None:
        idle_timeout = float(idle_timeout)
        max_duration = float(max_duration)
        if not math.isfinite(idle_timeout) or not math.isfinite(max_duration):
            raise ValueError("Flow timeouts must be finite numbers.")
        self.idle_timeout = max(0.1, idle_timeout)
        self.max_duration = max(self.idle_timeout, max_duration)
        self.max_pending_flows = max(1, int(max_pending_flows))
        self._flows: dict[tuple[Any, ...], _Flow] = {}
        self._expiry_heap: list[tuple[float, int, tuple[Any, ...]]] = []
        self._versions: dict[tuple[Any, ...], int] = {}
        self._version_ids = count()
        self._lock = RLock()
        self.unsupported_packets = 0
        self.dropped_flows = 0
        self._domain_by_ip: dict[str, tuple[str, float]] = {}
        self._port_scan_detector = PortScanDetector()
        self._live_rule_detector = LiveRuleDetector()

    def _observe_dns(self, packet: Any) -> None:
        try:
            from scapy.layers.dns import DNS, DNSRR

            if DNS not in packet:
                return
            dns = packet[DNS]
            if not int(dns.qr or 0) or not dns.an:
                return

            records = dns.an
            if isinstance(records, DNSRR):
                records = [records]
            for record in list(records)[:64]:
                if not isinstance(record, DNSRR):
                    continue
                if int(record.type) in (1, 28):
                    try:
                        address = str(ipaddress.ip_address(record.rdata))
                    except (TypeError, ValueError):
                        address = ""
                    raw_name = record.rrname
                    if isinstance(raw_name, bytes):
                        name = raw_name.decode("ascii").rstrip(".").lower()
                    else:
                        name = str(raw_name).rstrip(".").lower()
                    ttl = int(record.ttl or 0)
                    if address and name and len(name) <= 253 and ttl > 0:
                        self._domain_by_ip[address] = (
                            name,
                            time.monotonic() + min(ttl, 3600),
                        )
                        if len(self._domain_by_ip) > 4096:
                            self._domain_by_ip.pop(next(iter(self._domain_by_ip)))
        except (ImportError, AttributeError, TypeError, ValueError, OSError):
            return

    def _site_name(self, flow: _Flow) -> str | None:
        now = time.monotonic()
        for address in (flow.destination[0], flow.source[0]):
            cached = self._domain_by_ip.get(address)
            if cached is None:
                continue
            domain, expires_at = cached
            if expires_at > now:
                return domain
            self._domain_by_ip.pop(address, None)
        return None

    def _flow_features(self, flow: _Flow) -> Dict[str, Any]:
        features = flow.to_features()
        site_name = self._site_name(flow)
        if site_name:
            features["site_name"] = site_name
        return features

    @staticmethod
    def _key(source: tuple[str, int], destination: tuple[str, int], protocol: int) -> tuple[Any, ...]:
        return protocol, *sorted((source, destination))

    def add_packet(self, packet: Any) -> list[Dict[str, Any]]:
        self._observe_dns(packet)
        parts = _packet_parts(packet)
        if parts is None:
            self.unsupported_packets += 1
            return []
        source, destination, protocol, packet_bytes, timestamp = parts
        key = self._key(source, destination, protocol)
        completed: list[Dict[str, Any]] = []
        with self._lock:
            completed.extend(self._live_rule_detector.observe_packet(packet))
            if protocol == 6:
                from scapy.layers.inet import TCP

                if TCP in packet:
                    scan = self._port_scan_detector.observe_syn(
                        source[0],
                        destination[0],
                        destination[1],
                        int(packet[TCP].flags),
                        timestamp,
                    )
                    if scan is not None:
                        completed.append(scan)
            elif protocol == 17:
                from scapy.layers.inet import UDP

                if UDP in packet:
                    scan = self._port_scan_detector.observe_udp(
                        source[0],
                        destination[0],
                        destination[1],
                        timestamp,
                    )
                    if scan is not None:
                        completed.append(scan)

            while self._expiry_heap and self._expiry_heap[0][0] <= timestamp:
                _, version, flow_key = heapq.heappop(self._expiry_heap)
                if self._versions.get(flow_key) != version:
                    continue
                flow = self._flows.pop(flow_key, None)
                self._versions.pop(flow_key, None)
                if flow is not None:
                    completed.append(self._flow_features(flow))

            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= self.max_pending_flows:
                    self.dropped_flows += 1
                    return completed
                flow = _Flow(source, destination, protocol, timestamp, timestamp)
                self._flows[key] = flow
            flow.add(source, packet_bytes, timestamp)
            version = next(self._version_ids)
            self._versions[key] = version
            expiration = min(flow.last_seen + self.idle_timeout, flow.start + self.max_duration)
            heapq.heappush(self._expiry_heap, (expiration, version, key))
            if len(self._expiry_heap) > max(64, 4 * len(self._flows)):
                self._expiry_heap = [
                    (
                        min(
                            pending.last_seen + self.idle_timeout,
                            pending.start + self.max_duration,
                        ),
                        self._versions[pending_key],
                        pending_key,
                    )
                    for pending_key, pending in self._flows.items()
                ]
                heapq.heapify(self._expiry_heap)
        return completed

    def flush(self) -> list[Dict[str, Any]]:
        with self._lock:
            completed = [self._flow_features(flow) for flow in self._flows.values()]
            self._flows.clear()
            self._expiry_heap.clear()
            self._versions.clear()
        return completed

    @property
    def pending_flows(self) -> int:
        with self._lock:
            return len(self._flows)
