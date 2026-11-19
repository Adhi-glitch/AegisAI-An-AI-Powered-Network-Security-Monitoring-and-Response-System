"""
AegisAI Continuous Live Network Capture Monitor
Starts live packet capture and displays real-time flow stats in the terminal.
Keep this script running while you browse the web or demonstrate the system.
Press Ctrl+C to stop.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from dotenv import load_dotenv

load_dotenv()

BASE = "http://127.0.0.1:8000"


def api(path, method="GET", data=None, token=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(f"{BASE}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


def login():
    body = urllib.parse.urlencode({"username": os.getenv("AEGIS_ADMIN_USERNAME", "admin"), "password": os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")}).encode()
    req = urllib.request.Request(
        f"{BASE}/api/v1/auth/token", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]


def main():
    print("=" * 65)
    print("       AegisAI - Live Network Capture & Threat Detection")
    print("=" * 65)

    print("\n[1] Connecting to AegisAI Backend at", BASE, "...")
    try:
        token = login()
        print("  -> Authenticated successfully as Admin")
    except Exception as e:
        print(f"  -> ERROR: Cannot connect to backend: {e}")
        print("  -> Make sure the backend server is running in another terminal:")
        print("     .\\.venv\\Scripts\\python.exe -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload")
        sys.exit(1)

    # Check available interfaces
    ifaces_data = api("/api/v1/capture/interfaces", token=token)
    ifaces = ifaces_data.get("interfaces", [])
    print(f"\n[2] Found {len(ifaces)} network interfaces via Npcap")

    # Start capture on Wi-Fi (fallback to default if not found)
    print("\n[3] Activating live packet sniffer on Wi-Fi adapter...")
    start_res = api(
        "/api/v1/capture/start",
        method="POST",
        token=token,
        data={"interface": "Wi-Fi", "bpf_filter": "ip", "idle_timeout": 2.0}
    )
    status = start_res.get("status", "unknown")
    print(f"  -> Capture Sensor Status: {status.upper()}")

    if status not in ("running", "starting"):
        print("  -> WARNING: Could not start capture on 'Wi-Fi'. Trying default interface...")
        start_res = api(
            "/api/v1/capture/start",
            method="POST",
            token=token,
            data={"interface": None, "bpf_filter": "ip", "idle_timeout": 2.0}
        )
        status = start_res.get("status", "unknown")
        print(f"  -> Default Interface Status: {status.upper()}")

    print("\n" + "-" * 65)
    print("  LIVE SENSOR IS NOW ACTIVE!")
    print("  Open your dashboard at: http://localhost:8000")
    print("  Browse websites (YouTube, Google, etc.) to generate live traffic.")
    print("  Watch live packets & detections update below.")
    print("  Press Ctrl+C to stop capture.")
    print("-" * 65 + "\n")

    prev_flows = 0
    try:
        while True:
            time.sleep(2.5)
            st = api("/api/v1/capture/status", token=token)
            packets = st.get("packet_count", 0)
            flows = st.get("flow_count", 0)

            # Get latest detection
            dets = api("/api/v1/detections?page=1&limit=1", token=token)
            latest_det = ""
            items = dets.get("items", [])
            if items:
                d = items[0]
                cls = d.get("predicted_class", "Unknown")
                conf = float(d.get("confidence", 0.0))
                latest_det = f" | Latest: {cls} ({conf:.1%})"

            new_flows = flows - prev_flows
            flow_indicator = f"(+{new_flows} new)" if new_flows > 0 else ""
            print(f"\r  [Live Monitor] Packets Sniffed: {packets:5d} | Flows Analyzed: {flows:4d} {flow_indicator:10s}{latest_det}", end="", flush=True)
            prev_flows = flows

    except KeyboardInterrupt:
        print("\n\n[!] Stopping live capture...")
        api("/api/v1/capture/stop", method="POST", token=token)
        print("[OK] Capture stopped safely. Backend remains active.")


if __name__ == "__main__":
    main()
