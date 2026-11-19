"""Bounded, packet-level behavior indicators for live capture."""
from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote_plus

from agents.detection.port_scan import PORT_SCAN_RULE_SOURCE

BOTNET_IOC_RULE_SOURCE = "botnet_ioc_rule"
BOTNET_BEACON_RULE_SOURCE = "periodic_beacon_rule"
DOS_RATE_RULE_SOURCE = "dos_syn_rate_rule"
DDOS_RATE_RULE_SOURCE = "ddos_syn_rate_rule"
DOS_PACKET_RATE_RULE_SOURCE = "dos_packet_rate_rule"
DDOS_PACKET_RATE_RULE_SOURCE = "ddos_packet_rate_rule"
AUTH_ATTEMPT_RULE_SOURCE = "auth_attempt_rule"
WEB_SIGNATURE_RULE_SOURCE = "http_signature_rule"
HTTP_RATE_RULE_SOURCE = "http_request_rate_rule"
SLOW_HTTP_RULE_SOURCE = "slow_http_header_rule"

RULE_DETECTION_LABELS = {
    PORT_SCAN_RULE_SOURCE: "Port Scan",
    BOTNET_IOC_RULE_SOURCE: "Botnet",
    BOTNET_BEACON_RULE_SOURCE: "Botnet",
    DOS_RATE_RULE_SOURCE: "DoS",
    DDOS_RATE_RULE_SOURCE: "DDoS",
    DOS_PACKET_RATE_RULE_SOURCE: "DoS",
    DDOS_PACKET_RATE_RULE_SOURCE: "DDoS",
    AUTH_ATTEMPT_RULE_SOURCE: "Brute Force",
    WEB_SIGNATURE_RULE_SOURCE: "Web Attack",
    HTTP_RATE_RULE_SOURCE: "DoS",
    SLOW_HTTP_RULE_SOURCE: "DoS",
}

SYN_RATE_WINDOW_SECONDS = 5
DOS_SYN_THRESHOLD = 250
DDOS_SYN_THRESHOLD = 1000
DDOS_SOURCE_THRESHOLD = 5
DOS_PACKET_THRESHOLD = 250
DDOS_PACKET_THRESHOLD = 1000
AUTH_ATTEMPT_WINDOW_SECONDS = 60.0
AUTH_ATTEMPT_THRESHOLD = 10
HTTP_REQUEST_WINDOW_SECONDS = 5.0
HTTP_REQUEST_THRESHOLD = 200
SLOW_HTTP_MIN_AGE_SECONDS = 10.0
SLOW_HTTP_CONNECTION_THRESHOLD = 20
HTTP_STREAM_IDLE_SECONDS = 30.0
BEACON_MIN_INTERVAL_SECONDS = 5.0
BEACON_MAX_INTERVAL_SECONDS = 300.0
BEACON_INTERVAL_COUNT = 5
BEACON_MAX_RELATIVE_JITTER = 0.2
RULE_COOLDOWN_SECONDS = 60.0

_MAX_TRACKED_TARGETS = 1024
_MAX_SOURCES_PER_TARGET = 512
_MAX_AUTH_KEYS = 1024
_MAX_AUTH_SOURCE_PORTS = 128
_MAX_HTTP_STREAMS = 1024
_MAX_HTTP_BUFFER_BYTES = 8192
_MAX_HTTP_RATE_KEYS = 1024
_MAX_BEACON_KEYS = 4096
_MAX_RULE_COOLDOWNS = 4096
_DEFAULT_IOC_FILE = Path(__file__).resolve().parents[2] / "config" / "threat_iocs.json"
_AUTH_SERVICE_PORTS = frozenset({21, 22, 23, 25, 110, 143, 3389, 5900})
_HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8081, 8888})
_HTTP_REQUEST_LINE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/1\.[01]\r?\n",
    re.IGNORECASE,
)
_HTTP_ATTACK_SIGNATURES = (
    (
        "sql_union_select",
        re.compile(r"\bunion\b.{0,32}\bselect\b", re.IGNORECASE | re.DOTALL),
    ),
    (
        "sql_boolean_tautology",
        re.compile(
            r"\b(?:and|or)\s+['\"]?\d{1,6}['\"]?\s*=\s*['\"]?\d{1,6}['\"]?",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_timing_function",
        re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
    ),
    ("script_tag", re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("path_traversal", re.compile(r"(?:\.\./){2,}", re.IGNORECASE)),
)
_SYN = 0x02
_ACK = 0x10


@dataclass
class _RateBucket:
    second: int
    source_counts: Counter[str] = field(default_factory=Counter)


@dataclass
class _RateWindow:
    buckets: deque[_RateBucket] = field(default_factory=deque)
    source_counts: Counter[str] = field(default_factory=Counter)
    packet_count: int = 0
    last_dos_alert: dict[str, float] = field(default_factory=dict)
    last_ddos_alert: float = -math.inf


@dataclass
class _AuthWindow:
    source_ports: dict[int, float] = field(default_factory=dict)
    last_alert: float = -math.inf


@dataclass
class _HTTPStream:
    started_at: float
    updated_at: float
    payload: bytes


@dataclass
class _BeaconWindow:
    last_seen: float
    intervals: deque[float] = field(default_factory=deque)


def is_rule_detection(detection_source: Any, predicted_class: Any = None) -> bool:
    """Return whether a persisted event matches one of this module's rules."""
    if not isinstance(detection_source, str):
        return False
    label = RULE_DETECTION_LABELS.get(detection_source)
    return label is not None and (predicted_class is None or predicted_class == label)


class LiveRuleDetector:
    """Detect bounded traffic patterns without treating them as ML predictions."""

    def __init__(self, ioc_file: Path | str | None = None) -> None:
        self._rate_windows: OrderedDict[tuple[str, int, int], _RateWindow] = OrderedDict()
        self._auth_windows: OrderedDict[tuple[str, str, int], _AuthWindow] = OrderedDict()
        self._http_streams: OrderedDict[
            tuple[str, str, int, int], _HTTPStream
        ] = OrderedDict()
        self._http_rate_windows: OrderedDict[
            tuple[str, str, int], deque[tuple[float, int]]
        ] = OrderedDict()
        self._beacon_windows: OrderedDict[
            tuple[str, str, int, int], _BeaconWindow
        ] = OrderedDict()
        self._cooldowns: OrderedDict[tuple[Any, ...], float] = OrderedDict()
        self._ioc_domains, self._ioc_ips = self._load_iocs(ioc_file or _DEFAULT_IOC_FILE)

    @staticmethod
    def _load_iocs(ioc_file: Path | str) -> tuple[frozenset[str], frozenset[str]]:
        path = Path(ioc_file)
        with path.open(encoding="utf-8") as source:
            indicators = json.load(source)
        if not isinstance(indicators, dict):
            raise ValueError(f"Threat IOC file must contain a JSON object: {path}")

        raw_domains = indicators.get("domains", [])
        raw_ips = indicators.get("ips", [])
        if not isinstance(raw_domains, list) or not isinstance(raw_ips, list):
            raise ValueError(f"Threat IOC 'domains' and 'ips' must be arrays: {path}")

        domains: set[str] = set()
        for value in raw_domains:
            if not isinstance(value, str):
                raise ValueError(f"Threat IOC domain entries must be strings: {path}")
            domain = value.strip().rstrip(".").casefold()
            if not domain or len(domain) > 253 or any(char.isspace() for char in domain):
                raise ValueError(f"Invalid threat IOC domain in {path}")
            domains.add(domain)

        ips: set[str] = set()
        for value in raw_ips:
            if not isinstance(value, str):
                raise ValueError(f"Threat IOC IP entries must be strings: {path}")
            try:
                ips.add(str(ipaddress.ip_address(value.strip())))
            except ValueError as exc:
                raise ValueError(f"Invalid threat IOC IP in {path}: {value!r}") from exc
        return frozenset(domains), frozenset(ips)

    def observe_packet(self, packet: Any) -> list[dict[str, Any]]:
        """Return any behavior indicators supported by this packet."""
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.packet import Raw

        if IP not in packet:
            return []

        ip = packet[IP]
        try:
            timestamp = float(packet.time)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return []
        if not math.isfinite(timestamp) or timestamp < 0:
            return []

        source_ip = str(ip.src)
        destination_ip = str(ip.dst)
        protocol = int(ip.proto)
        source_port = 0
        destination_port = 0
        if TCP in packet:
            try:
                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return []
        elif UDP in packet:
            try:
                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return []

        events = self._observe_iocs(
            packet,
            source_ip,
            destination_ip,
            destination_port,
            protocol,
            timestamp,
            DNS,
            DNSQR,
        )
        if TCP in packet:
            tcp = packet[TCP]
            flags = int(tcp.flags)
            is_initial_syn = bool(flags & _SYN) and not bool(flags & _ACK)

            if is_initial_syn:
                events.extend(
                    self._observe_syn_rate(
                        source_ip,
                        destination_ip,
                        destination_port,
                        protocol,
                        timestamp,
                    )
                )
                if destination_port in _AUTH_SERVICE_PORTS:
                    auth_event = self._observe_auth_attempt(
                        source_ip,
                        destination_ip,
                        destination_port,
                        source_port,
                        timestamp,
                    )
                    if auth_event is not None:
                        events.append(auth_event)

                beacon = self._observe_beacon(
                    source_ip,
                    destination_ip,
                    destination_port,
                    protocol,
                    timestamp,
                )
                if beacon is not None:
                    events.append(beacon)

            if Raw in packet and destination_port in _HTTP_PORTS:
                payload = bytes(packet[Raw].load)
                if payload:
                    events.extend(
                        self._observe_http_request(
                            source_ip,
                            destination_ip,
                            source_port,
                            destination_port,
                            payload,
                            timestamp,
                        )
                    )
        elif UDP in packet or protocol == 1:
            events.extend(
                self._observe_packet_rate(
                    source_ip,
                    destination_ip,
                    destination_port,
                    protocol,
                    timestamp,
                )
            )
            if UDP in packet and destination_port != 53:
                beacon = self._observe_beacon(
                    source_ip,
                    destination_ip,
                    destination_port,
                    protocol,
                    timestamp,
                )
                if beacon is not None:
                    events.append(beacon)

        return events

    def _observe_iocs(
        self,
        packet: Any,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: int,
        timestamp: float,
        dns_layer: type,
        dns_question_layer: type,
    ) -> list[dict[str, Any]]:
        matches: list[tuple[str, str]] = []
        for address in (source_ip, destination_ip):
            if address in self._ioc_ips:
                matches.append(("ip", address))

        if dns_layer in packet:
            dns = packet[dns_layer]
            if not int(dns.qr or 0) and dns.qd:
                questions = dns.qd
                if isinstance(questions, dns_question_layer):
                    questions = [questions]
                for question in list(questions)[:8]:
                    if not isinstance(question, dns_question_layer):
                        continue
                    raw_name = question.qname
                    if isinstance(raw_name, bytes):
                        domain = raw_name.decode("ascii", errors="ignore")
                    else:
                        domain = str(raw_name)
                    domain = domain.rstrip(".\x00").casefold()
                    match = self._matching_domain_ioc(domain)
                    if match:
                        matches.append(("domain", match))

        events = []
        for ioc_type, ioc_value in matches:
            cooldown_key = (
                BOTNET_IOC_RULE_SOURCE,
                source_ip,
                destination_ip,
                ioc_type,
                ioc_value,
            )
            if not self._cooldown_allows(cooldown_key, timestamp):
                continue
            events.append(
                self._rule_event(
                    source_ip=source_ip,
                    dest_ip=destination_ip,
                    dest_port=destination_port,
                    protocol=protocol,
                    predicted="Botnet",
                    detection_source=BOTNET_IOC_RULE_SOURCE,
                    severity="high",
                    indicator="configured_threat_intelligence_ioc",
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    evidence_note="Matched a locally configured threat-intelligence indicator.",
                )
            )
        return events

    def _matching_domain_ioc(self, domain: str) -> str | None:
        labels = domain.split(".")
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in self._ioc_domains:
                return candidate
        return None

    def _rate_state(self, key: tuple[str, int, int]) -> _RateWindow:
        state = self._rate_windows.get(key)
        if state is None:
            if len(self._rate_windows) >= _MAX_TRACKED_TARGETS:
                self._rate_windows.popitem(last=False)
            state = _RateWindow()
            self._rate_windows[key] = state
        else:
            self._rate_windows.move_to_end(key)
        return state

    @staticmethod
    def _rule_event(
        *,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        protocol: int = 6,
        predicted: str,
        detection_source: str,
        severity: str,
        indicator: str,
        **metrics: Any,
    ) -> dict[str, Any]:
        return {
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol,
            "predicted": predicted,
            "confidence": None,
            "severity": severity,
            "detection_source": detection_source,
            "indicator": indicator,
            **metrics,
        }

    def _observe_syn_rate(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: int,
        timestamp: float,
    ) -> list[dict[str, Any]]:
        key = (destination_ip, destination_port, protocol)
        state = self._rate_state(key)
        second = int(timestamp)
        if state.buckets and second < state.buckets[-1].second:
            return []

        while state.buckets and second - state.buckets[0].second >= SYN_RATE_WINDOW_SECONDS:
            expired = state.buckets.popleft()
            for source, count in expired.source_counts.items():
                state.source_counts[source] -= count
                if state.source_counts[source] <= 0:
                    del state.source_counts[source]
            state.packet_count -= sum(expired.source_counts.values())

        if source_ip not in state.source_counts and len(state.source_counts) >= _MAX_SOURCES_PER_TARGET:
            return []
        if not state.buckets or state.buckets[-1].second != second:
            state.buckets.append(_RateBucket(second))
        bucket = state.buckets[-1]
        bucket.source_counts[source_ip] += 1
        state.source_counts[source_ip] += 1
        state.packet_count += 1

        events: list[dict[str, Any]] = []
        distributed_attack = (
            state.packet_count >= DDOS_SYN_THRESHOLD
            and len(state.source_counts) >= DDOS_SOURCE_THRESHOLD
        )
        if (
            distributed_attack
            and timestamp - state.last_ddos_alert >= RULE_COOLDOWN_SECONDS
        ):
            state.last_ddos_alert = timestamp
            events.append(
                self._rule_event(
                    source_ip="multiple",
                    dest_ip=destination_ip,
                    dest_port=destination_port,
                    predicted="DDoS",
                    detection_source=DDOS_RATE_RULE_SOURCE,
                    severity="high",
                    indicator="distributed_initial_syn_rate",
                    packet_count=state.packet_count,
                    distinct_source_count=len(state.source_counts),
                    source_ips=sorted(state.source_counts)[:16],
                    window_seconds=SYN_RATE_WINDOW_SECONDS,
                )
            )

        source_count = state.source_counts[source_ip]
        last_alert = state.last_dos_alert.get(source_ip, -math.inf)
        if (
            not distributed_attack
            and source_count >= DOS_SYN_THRESHOLD
            and timestamp - last_alert >= RULE_COOLDOWN_SECONDS
        ):
            state.last_dos_alert[source_ip] = timestamp
            events.append(
                self._rule_event(
                    source_ip=source_ip,
                    dest_ip=destination_ip,
                    dest_port=destination_port,
                    predicted="DoS",
                    detection_source=DOS_RATE_RULE_SOURCE,
                    severity="medium",
                    indicator="high_initial_syn_rate",
                    packet_count=source_count,
                    distinct_source_count=len(state.source_counts),
                    window_seconds=SYN_RATE_WINDOW_SECONDS,
                )
            )
        return events

    def _observe_packet_rate(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: int,
        timestamp: float,
    ) -> list[dict[str, Any]]:
        key = (destination_ip, destination_port, protocol)
        state = self._rate_state(key)
        second = int(timestamp)
        if state.buckets and second < state.buckets[-1].second:
            return []

        while state.buckets and second - state.buckets[0].second >= SYN_RATE_WINDOW_SECONDS:
            expired = state.buckets.popleft()
            for source, count in expired.source_counts.items():
                state.source_counts[source] -= count
                if state.source_counts[source] <= 0:
                    del state.source_counts[source]
            state.packet_count -= sum(expired.source_counts.values())

        if source_ip not in state.source_counts and len(state.source_counts) >= _MAX_SOURCES_PER_TARGET:
            return []
        if not state.buckets or state.buckets[-1].second != second:
            state.buckets.append(_RateBucket(second))
        bucket = state.buckets[-1]
        bucket.source_counts[source_ip] += 1
        state.source_counts[source_ip] += 1
        state.packet_count += 1

        events: list[dict[str, Any]] = []
        distributed_attack = (
            state.packet_count >= DDOS_PACKET_THRESHOLD
            and len(state.source_counts) >= DDOS_SOURCE_THRESHOLD
        )
        if (
            distributed_attack
            and timestamp - state.last_ddos_alert >= RULE_COOLDOWN_SECONDS
        ):
            state.last_ddos_alert = timestamp
            events.append(
                self._rule_event(
                    source_ip="multiple",
                    dest_ip=destination_ip,
                    dest_port=destination_port,
                    protocol=protocol,
                    predicted="DDoS",
                    detection_source=DDOS_PACKET_RATE_RULE_SOURCE,
                    severity="high",
                    indicator="distributed_packet_rate",
                    packet_count=state.packet_count,
                    distinct_source_count=len(state.source_counts),
                    source_ips=sorted(state.source_counts)[:16],
                    window_seconds=SYN_RATE_WINDOW_SECONDS,
                )
            )

        source_count = state.source_counts[source_ip]
        last_alert = state.last_dos_alert.get(source_ip, -math.inf)
        if (
            not distributed_attack
            and source_count >= DOS_PACKET_THRESHOLD
            and timestamp - last_alert >= RULE_COOLDOWN_SECONDS
        ):
            state.last_dos_alert[source_ip] = timestamp
            events.append(
                self._rule_event(
                    source_ip=source_ip,
                    dest_ip=destination_ip,
                    dest_port=destination_port,
                    protocol=protocol,
                    predicted="DoS",
                    detection_source=DOS_PACKET_RATE_RULE_SOURCE,
                    severity="medium",
                    indicator="high_packet_rate",
                    packet_count=source_count,
                    distinct_source_count=len(state.source_counts),
                    window_seconds=SYN_RATE_WINDOW_SECONDS,
                )
            )
        return events

    def _observe_beacon(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: int,
        timestamp: float,
    ) -> dict[str, Any] | None:
        key = (source_ip, destination_ip, destination_port, protocol)
        state = self._beacon_windows.get(key)
        if state is None:
            if len(self._beacon_windows) >= _MAX_BEACON_KEYS:
                self._beacon_windows.popitem(last=False)
            self._beacon_windows[key] = _BeaconWindow(last_seen=timestamp)
            return None

        self._beacon_windows.move_to_end(key)
        interval = timestamp - state.last_seen
        state.last_seen = timestamp
        if interval < BEACON_MIN_INTERVAL_SECONDS or interval > BEACON_MAX_INTERVAL_SECONDS:
            state.intervals.clear()
            return None

        state.intervals.append(interval)
        if len(state.intervals) > BEACON_INTERVAL_COUNT:
            state.intervals.popleft()
        if len(state.intervals) < BEACON_INTERVAL_COUNT:
            return None

        mean_interval = sum(state.intervals) / len(state.intervals)
        if mean_interval <= 0:
            return None
        relative_jitter = max(abs(value - mean_interval) for value in state.intervals) / mean_interval
        if relative_jitter > BEACON_MAX_RELATIVE_JITTER:
            return None

        cooldown_key = (BOTNET_BEACON_RULE_SOURCE, *key)
        if not self._cooldown_allows(cooldown_key, timestamp):
            return None
        return self._rule_event(
            source_ip=source_ip,
            dest_ip=destination_ip,
            dest_port=destination_port,
            protocol=protocol,
            predicted="Botnet",
            detection_source=BOTNET_BEACON_RULE_SOURCE,
            severity="low",
            indicator="repeated_periodic_connections",
            interval_seconds=round(mean_interval, 3),
            interval_count=len(state.intervals),
            relative_jitter=round(relative_jitter, 3),
            evidence_note=(
                "Repeated connections at a stable interval; periodic benign services "
                "can produce the same pattern."
            ),
        )

    def _observe_auth_attempt(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        source_port: int,
        timestamp: float,
    ) -> dict[str, Any] | None:
        key = (source_ip, destination_ip, destination_port)
        state = self._auth_windows.get(key)
        if state is None:
            if len(self._auth_windows) >= _MAX_AUTH_KEYS:
                self._auth_windows.popitem(last=False)
            state = _AuthWindow()
            self._auth_windows[key] = state
        else:
            self._auth_windows.move_to_end(key)

        cutoff = timestamp - AUTH_ATTEMPT_WINDOW_SECONDS
        state.source_ports = {
            port: seen_at
            for port, seen_at in state.source_ports.items()
            if seen_at >= cutoff
        }
        if source_port not in state.source_ports:
            if len(state.source_ports) >= _MAX_AUTH_SOURCE_PORTS:
                oldest_port = min(state.source_ports, key=state.source_ports.get)
                state.source_ports.pop(oldest_port)
            state.source_ports[source_port] = timestamp

        if (
            len(state.source_ports) < AUTH_ATTEMPT_THRESHOLD
            or timestamp - state.last_alert < RULE_COOLDOWN_SECONDS
        ):
            return None

        attempt_count = len(state.source_ports)
        state.last_alert = timestamp
        state.source_ports.clear()
        return self._rule_event(
            source_ip=source_ip,
            dest_ip=destination_ip,
            dest_port=destination_port,
            predicted="Brute Force",
            detection_source=AUTH_ATTEMPT_RULE_SOURCE,
            severity="low",
            indicator="repeated_auth_service_connections",
            distinct_connection_attempts=attempt_count,
            window_seconds=AUTH_ATTEMPT_WINDOW_SECONDS,
            evidence_note=(
                "Repeated connections to an authentication-service port; "
                "packet capture cannot confirm login failures."
            ),
        )

    def _observe_http_request(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        payload: bytes,
        timestamp: float,
    ) -> list[dict[str, Any]]:
        key = (source_ip, destination_ip, source_port, destination_port)
        previous = self._http_streams.get(key)
        if previous is None or timestamp - previous.updated_at > HTTP_STREAM_IDLE_SECONDS:
            combined = payload[:_MAX_HTTP_BUFFER_BYTES]
            started_at = timestamp
        else:
            combined = (previous.payload + payload)[:_MAX_HTTP_BUFFER_BYTES]
            started_at = previous.started_at

        self._http_streams[key] = _HTTPStream(started_at, timestamp, combined)
        self._http_streams.move_to_end(key)
        if len(self._http_streams) > _MAX_HTTP_STREAMS:
            self._http_streams.popitem(last=False)

        events: list[dict[str, Any]] = []
        request = combined.decode("latin-1", errors="ignore")
        request_match = _HTTP_REQUEST_LINE.search(request)
        if request_match is None:
            return events

        rate_key = (source_ip, destination_ip, destination_port)
        rate_window = self._http_rate_windows.get(rate_key)
        if rate_window is None:
            if len(self._http_rate_windows) >= _MAX_HTTP_RATE_KEYS:
                self._http_rate_windows.popitem(last=False)
            rate_window = deque(maxlen=HTTP_REQUEST_THRESHOLD)
            self._http_rate_windows[rate_key] = rate_window
        else:
            self._http_rate_windows.move_to_end(rate_key)
        cutoff = timestamp - HTTP_REQUEST_WINDOW_SECONDS
        while rate_window and rate_window[0][0] < cutoff:
            rate_window.popleft()
        if not any(port == source_port for _, port in rate_window):
            rate_window.append((timestamp, source_port))
        if (
            len(rate_window) >= HTTP_REQUEST_THRESHOLD
            and self._cooldown_allows(("http_rate", *rate_key), timestamp)
        ):
            events.append(
                self._rule_event(
                    source_ip=source_ip,
                    dest_ip=destination_ip,
                    dest_port=destination_port,
                    predicted="DoS",
                    detection_source=HTTP_RATE_RULE_SOURCE,
                    severity="medium",
                    indicator="high_http_request_rate",
                    request_count=len(rate_window),
                    window_seconds=HTTP_REQUEST_WINDOW_SECONDS,
                )
            )

        if b"\r\n\r\n" not in combined and timestamp - started_at >= SLOW_HTTP_MIN_AGE_SECONDS:
            incomplete_connections = sum(
                1
                for (stream_source, stream_dest, _, stream_port), stream in self._http_streams.items()
                if stream_source == source_ip
                and stream_dest == destination_ip
                and stream_port == destination_port
                and b"\r\n\r\n" not in stream.payload
                and timestamp - stream.started_at >= SLOW_HTTP_MIN_AGE_SECONDS
            )
            slow_key = ("slow_http", source_ip, destination_ip, destination_port)
            if (
                incomplete_connections >= SLOW_HTTP_CONNECTION_THRESHOLD
                and self._cooldown_allows(slow_key, timestamp)
            ):
                events.append(
                    self._rule_event(
                        source_ip=source_ip,
                        dest_ip=destination_ip,
                        dest_port=destination_port,
                        predicted="DoS",
                        detection_source=SLOW_HTTP_RULE_SOURCE,
                        severity="medium",
                        indicator="many_long_lived_incomplete_http_headers",
                        concurrent_incomplete_connections=incomplete_connections,
                        minimum_age_seconds=SLOW_HTTP_MIN_AGE_SECONDS,
                        evidence_note=(
                            "Many incomplete cleartext HTTP headers remain open; "
                            "capture does not prove service impact."
                        ),
                    )
                )

        request_line = request_match.group(0).splitlines()[0]
        method, _, path = request_line.partition(" ")
        normalized_path = path.split("?", 1)[0].casefold()
        if method.casefold() == "post" and any(
            token in normalized_path for token in ("login", "signin", "auth", "session")
        ):
            auth_event = self._observe_auth_attempt(
                source_ip,
                destination_ip,
                destination_port,
                source_port,
                timestamp,
            )
            if auth_event is not None:
                events.append(auth_event)

        normalized = unquote_plus(request).casefold()
        indicator = next(
            (
                name
                for name, signature in _HTTP_ATTACK_SIGNATURES
                if signature.search(normalized)
            ),
            None,
        )
        if indicator is None:
            return events

        cooldown_key = (WEB_SIGNATURE_RULE_SOURCE, source_ip, destination_ip, destination_port, indicator)
        if not self._cooldown_allows(cooldown_key, timestamp):
            return events
        events.append(
            self._rule_event(
                source_ip=source_ip,
                dest_ip=destination_ip,
                dest_port=destination_port,
                predicted="Web Attack",
                detection_source=WEB_SIGNATURE_RULE_SOURCE,
                severity="medium",
                indicator=indicator,
                evidence_note=(
                    "High-specificity signature matched cleartext HTTP request data; "
                    "encrypted HTTPS payloads are not inspected."
                ),
            )
        )
        return events

    def _cooldown_allows(self, key: tuple[Any, ...], timestamp: float) -> bool:
        previous = self._cooldowns.get(key)
        if previous is not None and timestamp - previous < RULE_COOLDOWN_SECONDS:
            return False
        self._cooldowns[key] = timestamp
        self._cooldowns.move_to_end(key)
        if len(self._cooldowns) > _MAX_RULE_COOLDOWNS:
            self._cooldowns.popitem(last=False)
        return True
