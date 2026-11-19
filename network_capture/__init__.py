"""Scapy-based packet capture and flow emission for the live prototype."""
from __future__ import annotations

import os
import logging
from threading import RLock
import time
from typing import Any, Callable, Optional

from agents.feature_extraction.live_extractor import FlowTracker

FlowCallback = Callable[[dict[str, Any]], Any]
_LOGGER = logging.getLogger(__name__)
_LOCK = RLock()
_LIFECYCLE_LOCK = RLock()
_SNIFFER: Any = None
_TRACKER: Optional[FlowTracker] = None
_CAPTURED_CALLBACK: Optional[FlowCallback] = None
_STATUS: dict[str, Any] = {
    "status": "stopped",
    "interface": None,
    "filter": None,
    "started_at": None,
    "packet_count": 0,
    "flow_count": 0,
    "dropped_flows": 0,
    "callback_errors": 0,
    "last_error": None,
}


def _new_sniffer(**kwargs):
    from scapy.all import AsyncSniffer, conf

    if os.name == "nt" and not conf.use_pcap:
        raise RuntimeError("Scapy has no Npcap/libpcap provider. Install Npcap, then restart the backend.")

    return AsyncSniffer(**kwargs)


def _resolve_interface(interface: str | None) -> str | None:
    if interface is None:
        return None

    from scapy.all import conf

    for device in conf.ifaces.values():
        name = str(device.name)
        network_name = getattr(device, "network_name", None)
        if interface == name or interface == network_name:
            return name

    raise RuntimeError(f"Unknown capture interface: {interface}")


def _dispatch_flow(flow: dict[str, Any]) -> None:
    with _LOCK:
        callback = _CAPTURED_CALLBACK
    if callback is None:
        return
    try:
        callback(flow)
        with _LOCK:
            _STATUS["flow_count"] += 1
    except Exception as exc:
        _LOGGER.exception("Live-flow callback failed")
        with _LOCK:
            _STATUS["callback_errors"] += 1
            _STATUS["last_error"] = f"Live-flow callback failed: {exc}"


def _on_packet(packet: Any) -> None:
    with _LOCK:
        tracker = _TRACKER
        if tracker is None:
            return
        _STATUS["packet_count"] += 1
    try:
        completed_flows = tracker.add_packet(packet)
        with _LOCK:
            _STATUS["dropped_flows"] = tracker.dropped_flows
        for completed in completed_flows:
            _dispatch_flow(completed)
    except Exception as exc:
        _LOGGER.exception("Packet processing failed in the capture callback")
        with _LOCK:
            _STATUS["callback_errors"] += 1
            _STATUS["last_error"] = f"Packet processing failed: {exc}"


def start_capture(
    callback: FlowCallback,
    interface: str | None = None,
    bpf_filter: str = "ip",
    idle_timeout: float = 2.0,
) -> dict[str, Any]:
    """Start one asynchronous capture session and emit completed flow records."""
    global _CAPTURED_CALLBACK, _SNIFFER, _TRACKER, _STATUS
    if not callable(callback):
        raise TypeError("Capture callback must be callable.")
    try:
        resolved_interface = _resolve_interface(interface)
    except Exception as exc:
        raise RuntimeError(f"Could not resolve packet capture interface: {exc}") from exc
    with _LIFECYCLE_LOCK:
        with _LOCK:
            existing_sniffer = _SNIFFER
        if existing_sniffer is not None:
            try:
                if existing_sniffer.running:
                    return get_capture_status()
            except Exception as exc:
                raise RuntimeError(f"Could not inspect existing capture state: {exc}") from exc
            stop_capture()

        with _LOCK:
            _CAPTURED_CALLBACK = callback
            _STATUS = {
                "status": "starting",
                "interface": resolved_interface,
                "filter": bpf_filter,
                "started_at": time.time(),
                "packet_count": 0,
                "flow_count": 0,
                "dropped_flows": 0,
                "callback_errors": 0,
                "last_error": None,
            }
        sniffer = None
        try:
            tracker = FlowTracker(idle_timeout=idle_timeout)
            with _LOCK:
                _TRACKER = tracker
            sniffer = _new_sniffer(
                iface=resolved_interface,
                filter=bpf_filter,
                prn=_on_packet,
                store=False,
            )
            with _LOCK:
                _SNIFFER = sniffer
            sniffer.start()
            with _LOCK:
                _STATUS["status"] = "running"
        except Exception as exc:
            _LOGGER.exception("Could not start packet capture")
            if sniffer is not None:
                try:
                    if sniffer.running:
                        sniffer.stop()
                except Exception:
                    _LOGGER.exception("Failed to clean up a partially started sniffer")
            with _LOCK:
                _SNIFFER = None
                _TRACKER = None
                _CAPTURED_CALLBACK = None
                _STATUS["status"] = "error"
                _STATUS["last_error"] = str(exc)
            raise RuntimeError(f"Could not start packet capture: {exc}") from exc
        with _LOCK:
            return dict(_STATUS)


def stop_capture() -> dict[str, Any]:
    """Stop packet capture and synchronously emit remaining partial flows."""
    global _CAPTURED_CALLBACK, _SNIFFER, _TRACKER, _STATUS
    with _LIFECYCLE_LOCK:
        with _LOCK:
            sniffer = _SNIFFER
            tracker = _TRACKER
            _STATUS["status"] = "stopping"

        stop_error = None
        if sniffer is not None:
            try:
                if sniffer.running:
                    sniffer.stop()
                if sniffer.running:
                    raise RuntimeError("Packet sniffer remained active after stop.")
            except Exception as exc:
                stop_error = exc
                _LOGGER.exception("Could not stop packet capture")
                try:
                    if sniffer.running:
                        with _LOCK:
                            _STATUS["status"] = "error"
                            _STATUS["last_error"] = f"Could not stop packet capture: {exc}"
                            return dict(_STATUS)
                except Exception:
                    with _LOCK:
                        _STATUS["status"] = "error"
                        _STATUS["last_error"] = f"Could not inspect capture state after stop: {exc}"
                        return dict(_STATUS)

        try:
            if tracker is not None:
                for flow in tracker.flush():
                    _dispatch_flow(flow)
        except Exception as exc:
            stop_error = stop_error or exc
            _LOGGER.exception("Could not flush pending flows during capture shutdown")

        with _LOCK:
            _CAPTURED_CALLBACK = None
            _SNIFFER = None
            _TRACKER = None
            _STATUS["status"] = "error" if stop_error else "stopped"
            if stop_error:
                _STATUS["last_error"] = f"Capture shutdown was incomplete: {stop_error}"
            return dict(_STATUS)


def get_capture_status() -> dict[str, Any]:
    with _LOCK:
        if _SNIFFER is not None:
            try:
                running = bool(_SNIFFER.running)
                if running and _STATUS["status"] == "starting":
                    _STATUS["status"] = "running"
                elif not running and _STATUS["status"] == "running":
                    failure = getattr(_SNIFFER, "exception", None)
                    _STATUS["status"] = "error" if failure else "stopped"
                    if failure:
                        _STATUS["last_error"] = str(failure)
            except Exception as exc:
                _LOGGER.exception("Could not inspect capture status")
                _STATUS["status"] = "error"
                _STATUS["last_error"] = f"Could not inspect capture status: {exc}"
        return dict(_STATUS)


def get_interfaces() -> list[str]:
    """Return Scapy-resolvable interface names for UI selection."""
    from scapy.all import conf

    return sorted({str(interface.name) for interface in conf.ifaces.values()})
