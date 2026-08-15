"""Network capture helpers.

These functions are intentionally safe no-ops by default so the application can
start without a live packet source and still expose the expected interface for
future integration with scapy/pyshark.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

_CAPTURED_CALLBACK: Optional[Callable[[dict], Any]] = None


def start_capture(callback: Callable[[dict], Any]):
    """Register a packet callback and return a lightweight handle.

    For now, the capture is intentionally disabled. The function does not crash
    the application, which makes the project usable in environments where live
    capture is unavailable.
    """
    global _CAPTURED_CALLBACK
    _CAPTURED_CALLBACK = callback
    return {"status": "disabled", "message": "Live capture is not enabled"}


def stop_capture():
    """Stop any active capture session."""
    global _CAPTURED_CALLBACK
    _CAPTURED_CALLBACK = None
    return {"status": "stopped"}
