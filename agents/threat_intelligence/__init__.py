"""Threat intelligence enrichment helpers.

The project is intentionally designed to work without external TI providers, so
this function returns a structured default result rather than failing at runtime.
"""
from __future__ import annotations

from typing import Any, Dict


def enrich(ip: str) -> Dict[str, Any]:
    """Return a default enrichment payload for a source IP.

    The result is intentionally safe and serializable so the rest of the system
    can operate even when no external intelligence provider is configured.
    """
    normalized_ip = str(ip or "unknown").strip()
    return {
        "ip": normalized_ip,
        "reputation": "unknown",
        "severity": "info",
        "notes": "No external threat-intel feed configured; default safe result returned.",
        "sources": [],
    }
