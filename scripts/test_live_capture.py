r"""
AegisAI Live Capture Smoke Test
Run from Admin PowerShell while backend is running:
    .\.venv\Scripts\python.exe scripts\test_live_capture.py --interface "Wi-Fi"
"""
import argparse
import json
import time
import urllib.request
import os
from dotenv import load_dotenv

load_dotenv()
import urllib.parse
import urllib.error

BASE = "http://127.0.0.1:8000"

parser = argparse.ArgumentParser(description="Smoke-test live packet capture and persistence.")
parser.add_argument("--interface", required=True, help="Friendly interface name returned by the capture API")
args = parser.parse_args()


def api(path, method="GET", data=None, token=None, timeout=15):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(f"{BASE}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "detail": e.read().decode()}
    except Exception as e:
        return {"error": str(e)}


def form_post(path, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        f"{BASE}{path}", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


print("=" * 60)
print("  AegisAI Live Capture Smoke Test")
print("=" * 60)

# 1. Login
print("\n[1] Authenticating as admin...")
try:
    tok = form_post("/api/v1/auth/token", {"username": os.getenv("AEGIS_ADMIN_USERNAME", "admin"), "password": os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")})
except Exception as e:
    print(f"  FAILED: Cannot reach backend at {BASE}")
    print(f"  Error: {e}")
    print("\n  >>> Make sure you started the backend first:")
    print("  .\\.venv\\Scripts\\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload")
    exit(1)

if "access_token" not in tok:
    print("  FAILED: Wrong credentials or backend error:", tok)
    exit(1)

token = tok["access_token"]
print("  OK - Logged in as admin")

# 2. Health check
print("\n[2] Backend health check...")
health = api("/api/v1/health", token=token)
print(f"  Status: {health.get('status')} | Model loaded: {health.get('model_loaded')}")

# 3. List interfaces
print("\n[3] Available network interfaces (Npcap detected):")
ifaces = api("/api/v1/capture/interfaces", token=token)
available_interfaces = ifaces.get("interfaces", [])
for iface in available_interfaces:
    print(f"  - {iface}")
if args.interface not in available_interfaces:
    print(f"  FAILED: Interface {args.interface!r} is not in the available list.")
    exit(1)

# 4. Start capture on the selected interface
print(f"\n[4] Starting live capture on {args.interface}...")
result = api("/api/v1/capture/start", method="POST", token=token,
             data={"interface": args.interface, "bpf_filter": "ip", "idle_timeout": 2.0})
status = result.get("status", "unknown")
print(f"  Status: {status} | Error: {result.get('last_error', 'None')}")

if status not in ("running", "starting"):
    print("  FAILED: Could not start capture.")
    print("  Make sure you are running as Administrator!")
    exit(1)

# 5. Generate traffic
print("\n[5] Generating real HTTP traffic...")
test_urls = ["http://example.com", "http://httpbin.org/get"]
for url in test_urls:
    try:
        urllib.request.urlopen(url, timeout=5)
        print(f"  Pinged: {url}")
    except Exception as e:
        print(f"  {url}: {e}")

print("\n[6] Waiting 8 seconds for flows to be processed by ML model...")
time.sleep(8)

# 7. Stats
print("\n[7] Capture statistics:")
status_data = api("/api/v1/capture/status", token=token)
packets = status_data.get("packet_count", 0)
flows = status_data.get("flow_count", 0)
errors = status_data.get("callback_errors", 0)
print(f"  Packets captured : {packets}")
print(f"  Flows processed  : {flows}")
print(f"  Errors           : {errors}")
print(f"  Last error       : {status_data.get('last_error', 'None')}")

# 8. Stop capture
print("\n[8] Stopping capture...")
stop_result = api("/api/v1/capture/stop", method="POST", token=token, timeout=20)
print(f"  Stop result: {stop_result.get('status', stop_result)}")

# 9. Check DB for alerts
print("\n[9] Verifying alerts were saved to database...")
alerts = api("/api/v1/alerts?limit=5", token=token)
items = alerts.get("items", [])
print(f"  Total alerts in DB: {alerts.get('total', 0)}")
for a in items[:3]:
    print(f"  -> {a.get('source_ip')} => {a.get('dest_ip')} (proto: {a.get('protocol')})")

# 10. Check detections
print("\n[10] Verifying ML detections were saved...")
dets = api("/api/v1/detections?limit=5", token=token)
det_items = dets.get("items", [])
print(f"  Total detections in DB: {dets.get('total', 0)}")
for d in det_items[:3]:
    print(f"  -> Class: {d.get('predicted_class')} | Confidence: {float(d.get('confidence', 0)):.1%}")

# Summary
print("\n" + "=" * 60)
if packets > 0 and flows > 0:
    print("  RESULT: SUCCESS - Full pipeline is WORKING!")
    print(f"  {packets} packets captured -> {flows} flows analyzed by ML model")
    print(f"  {alerts.get('total', 0)} alerts and {dets.get('total', 0)} detections saved")
elif packets == 0:
    print("  RESULT: No packets captured.")
    print("  Make sure you are running as Administrator.")
else:
    print("  RESULT: Packets captured but no flows emitted yet.")
    print("  Try running again and browsing the web during the wait.")
print("=" * 60)
print("\nNow open: http://127.0.0.1:5173  -> Alerts / Detections pages")
print("to see your captured traffic in the dashboard!")
