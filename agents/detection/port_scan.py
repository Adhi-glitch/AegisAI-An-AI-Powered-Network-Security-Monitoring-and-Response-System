"""Bounded behavioral detection for TCP SYN port scans."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field


PORT_SCAN_RULE_SOURCE = "port_scan_rule"
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW_SECONDS = 60.0
PORT_SCAN_COOLDOWN_SECONDS = 60.0
_MAX_TRACKED_ENDPOINT_PAIRS = 1024
_MAX_TRACKED_PORTS_PER_PAIR = 256
_TCP_SYN = 0x02
_TCP_ACK = 0x10


@dataclass
class _ScanWindow:
    port_timestamps: dict[int, float] = field(default_factory=dict)
    suppressed_until: float = 0.0


class PortScanDetector:
    """Emit one low-severity signal per source/target pair per scan window."""

    def __init__(self) -> None:
        self._windows: OrderedDict[tuple[str, str, int], _ScanWindow] = OrderedDict()

    def observe_syn(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        tcp_flags: int,
        timestamp: float,
    ) -> dict[str, int | float | str] | None:
        """Detect 20 distinct TCP SYN target ports within a rolling 60 seconds."""
        if not (tcp_flags & _TCP_SYN) or (tcp_flags & _TCP_ACK):
            return None
        return self._observe_distinct_port(
            source_ip,
            destination_ip,
            destination_port,
            timestamp,
            protocol=6,
        )

    def observe_udp(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        timestamp: float,
    ) -> dict[str, int | float | str] | None:
        """Detect 20 distinct UDP destination ports within a rolling 60 seconds."""
        return self._observe_distinct_port(
            source_ip,
            destination_ip,
            destination_port,
            timestamp,
            protocol=17,
        )

    def _observe_distinct_port(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        timestamp: float,
        *,
        protocol: int,
    ) -> dict[str, int | float | str] | None:
        if not 1 <= destination_port <= 65535:
            return None

        key = (source_ip, destination_ip, protocol)
        window = self._windows.get(key)
        if window is None:
            if len(self._windows) >= _MAX_TRACKED_ENDPOINT_PAIRS:
                self._windows.popitem(last=False)
            window = _ScanWindow()
            self._windows[key] = window
        else:
            self._windows.move_to_end(key)

        if timestamp < window.suppressed_until:
            return None
        if window.suppressed_until:
            window.port_timestamps.clear()
            window.suppressed_until = 0.0

        cutoff = timestamp - PORT_SCAN_WINDOW_SECONDS
        window.port_timestamps = {
            port: seen_at
            for port, seen_at in window.port_timestamps.items()
            if seen_at >= cutoff
        }
        if len(window.port_timestamps) < _MAX_TRACKED_PORTS_PER_PAIR:
            window.port_timestamps[destination_port] = max(
                timestamp,
                window.port_timestamps.get(destination_port, timestamp),
            )

        distinct_ports = len(window.port_timestamps)
        if distinct_ports < PORT_SCAN_THRESHOLD:
            return None

        window.port_timestamps.clear()
        window.suppressed_until = timestamp + PORT_SCAN_COOLDOWN_SECONDS
        return {
            "source_ip": source_ip,
            "dest_ip": destination_ip,
            "protocol": protocol,
            "predicted": "Port Scan",
            "confidence": None,
            "severity": "low",
            "detection_source": PORT_SCAN_RULE_SOURCE,
            "distinct_destination_ports": distinct_ports,
            "window_seconds": PORT_SCAN_WINDOW_SECONDS,
        }
