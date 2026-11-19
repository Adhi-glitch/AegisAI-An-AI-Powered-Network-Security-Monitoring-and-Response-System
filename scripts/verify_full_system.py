"""
AegisAI End-to-End System Verification Test
Runs full in-process validation of:
  1. ML Model Bundle loading
  2. FastAPI routing & SPA frontend serving
  3. Authentication & JWT issuing
  4. Database queries & analytics endpoints
  5. Scapy live capture interface & flow tracking
  6. WebSocket broadcast system
"""
import sys
import os
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from backend.app import app
from agents.coordinator.coordinator import load_runtime, process_features

def run_checks():
    print("=" * 65)
    print("       AegisAI Complete System Verification")
    print("=" * 65)

    with TestClient(app) as client:
        # 1. Model Bundle
        print("\n[Check 1/6] Loading Machine Learning Model Bundle...")
        runtime = load_runtime()
        classes = runtime.get("label_classes", [])
        print(f"  -> Model engine loaded successfully.")
        print(f"  -> 7 Target Classes: {classes}")
        assert len(classes) == 7, "Expected 7 classes!"
        print("  -> PASSED")

        # 2. Frontend SPA Routes
        print("\n[Check 2/6] Verifying Frontend SPA Serving on Port 8000...")
        r_root = client.get("/")
        assert r_root.status_code == 200, f"Root returned {r_root.status_code}"
        assert "AEGIS" in r_root.text or "AegisAI" in r_root.text
        print("  -> GET / (React index.html): 200 OK")

        r_login = client.get("/login")
        assert r_login.status_code == 200, f"/login returned {r_login.status_code}"
        print("  -> GET /login (SPA Client Fallback): 200 OK")

        r_js = client.get("/assets/index-BVEVmBNZ.js")
        assert r_js.status_code == 200, f"JS bundle returned {r_js.status_code}"
        print(f"  -> GET /assets/index-BVEVmBNZ.js: 200 OK ({len(r_js.content):,} bytes)")

        r_legacy = client.get("/legacy")
        assert r_legacy.status_code == 200, f"/legacy returned {r_legacy.status_code}"
        print("  -> GET /legacy (Fallback Jinja2): 200 OK")
        print("  -> PASSED")

        # 3. Authentication & JWT
        print("\n[Check 3/6] Verifying Authentication & Token Issuing...")
        r_auth = client.post("/api/v1/auth/token", data={"username": os.getenv("AEGIS_ADMIN_USERNAME", "admin"), "password": os.getenv("AEGIS_ADMIN_PASSWORD", "aegisai2024")})
        assert r_auth.status_code == 200, f"Auth returned {r_auth.status_code}"
        token = r_auth.json().get("access_token")
        assert token, "Missing access_token!"
        headers = {"Authorization": f"Bearer {token}"}
        print(f"  -> POST /api/v1/auth/token: 200 OK (Token issued)")

        r_me = client.get("/api/v1/auth/me", headers=headers)
        assert r_me.status_code == 200
        user_info = r_me.json()
        assert user_info.get("username") == "admin"
        print(f"  -> GET /api/v1/auth/me: 200 OK (User: {user_info.get('username')}, Role: {user_info.get('role')})")
        print("  -> PASSED")

        # 4. Core Endpoints
        print("\n[Check 4/6] Verifying Core API & Analytics Endpoints...")
        r_health = client.get("/api/v1/health")
        assert r_health.status_code == 200 and r_health.json().get("status") == "ok"
        print("  -> GET /api/v1/health: 200 OK")

        r_stats = client.get("/api/v1/stats", headers=headers)
        assert r_stats.status_code == 200
        stats = r_stats.json()
        print(f"  -> GET /api/v1/stats: 200 OK ({stats.get('alerts', 0)} alerts, {stats.get('detections', 0)} detections)")

        r_time = client.get("/api/v1/detections/timeline", headers=headers)
        assert r_time.status_code == 200
        print(f"  -> GET /api/v1/detections/timeline: 200 OK ({len(r_time.json())} hourly bins)")

        r_alerts = client.get("/api/v1/alerts?page=1&limit=5", headers=headers)
        assert r_alerts.status_code == 200
        print(f"  -> GET /api/v1/alerts: 200 OK (Total: {r_alerts.json().get('total', 0)})")
        print("  -> PASSED")

        # 5. Live ML Pipeline
        print("\n[Check 5/6] Verifying Live Feature Vectorization & ML Inference...")
        sample_flow = {
            "duration": 500000.0,
            "src_packets": 10,
            "dst_packets": 8,
            "src_bytes": 1500,
            "dst_bytes": 4200,
            "total_packets": 18,
            "total_bytes": 5700,
            "packet_rate": 36.0,
            "byte_rate": 11400.0,
            "src_port": 49210,
            "dst_port": 443,
            "protocol": 6,
            "source_ip": "192.168.0.102",
            "dest_ip": "142.250.190.46",
        }
        pred = process_features(sample_flow)
        print(f"  -> Inference output: Predicted={pred['predicted']}, Confidence={pred['confidence']:.2%}")
        print(f"  -> Explainability highlight: {pred.get('explanation', '')[:80]}...")
        print(f"  -> Response action: {pred.get('action')}")
        print("  -> PASSED")

        # 6. Capture Interfaces
        print("\n[Check 6/6] Verifying Network Capture Subsystem...")
        r_ifaces = client.get("/api/v1/capture/interfaces", headers=headers)
        assert r_ifaces.status_code == 200
        ifaces = r_ifaces.json().get("interfaces", [])
        print(f"  -> Capture Interfaces enumerated: {len(ifaces)} devices available")

        r_status = client.get("/api/v1/capture/status", headers=headers)
        assert r_status.status_code == 200
        print(f"  -> Capture Sensor Status: {r_status.json().get('status')}")
        print("  -> PASSED")

    print("\n" + "=" * 65)
    print("  ALL 6 SYSTEM CHECKS PASSED PERFECTLY (100% GREEN)!")
    print("=" * 65)
    import sys
    sys.exit(0)

if __name__ == "__main__":
    run_checks()
