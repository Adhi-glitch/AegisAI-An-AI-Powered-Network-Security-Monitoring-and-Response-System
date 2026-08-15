"""Best-effort live packet extraction for scapy/pyshark packet objects."""
from __future__ import annotations

from typing import Any, Dict


def extract_from_packet(pkt) -> Dict[str, Any]:
    """Return a normalized dict when packet metadata is available.

    The implementation is intentionally defensive: it extracts common fields when
    a packet object exposes them and otherwise returns a safe empty dict.
    """
    if pkt is None:
        return {}

    data: Dict[str, Any] = {}

    for attr in ("time", "len", "length", "bytes", "summary"):
        if hasattr(pkt, attr):
            value = getattr(pkt, attr)
            if value is not None:
                data[attr] = value

    # Common scapy-like attributes
    for attr, key in {
        "src": "source_ip",
        "dst": "dest_ip",
        "sport": "source_port",
        "dport": "dest_port",
        "proto": "protocol",
    }.items():
        if hasattr(pkt, attr):
            value = getattr(pkt, attr)
            if value is not None:
                data[key] = value

    # Some packet objects expose a dictionary-like payload.
    if hasattr(pkt, "fields") and isinstance(pkt.fields, dict):
        for key, value in pkt.fields.items():
            if isinstance(value, (int, float, str)):
                data.setdefault(str(key), value)

    return data
