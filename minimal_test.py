#!/usr/bin/env python
"""Minimal test to isolate the hanging issue."""

print("1. Testing response engine module...")
from agents.response.response_engine import engine
print(f"   [OK] Response engine loaded: {engine}")

print("\n2. Testing basic response engine calls...")
result = engine.apply_action("192.168.1.1", "log")
print(f"   [OK] apply_action returned: {result}")

print("\n3. Testing database module...")
from database import models
print(f"   [OK] Database models loaded")

print("\n4. Testing database session...")
from database.init_db import SessionLocal, init_db
db = SessionLocal()
print(f"   [OK] Database session created")
db.close()
print(f"   [OK] Database session closed")

print("\n5. Testing FastAPI app import...")
from backend.app import app
print(f"   [OK] FastAPI app loaded")

print("\n6. Creating test client...")
from fastapi.testclient import TestClient
client = TestClient(app)
print(f"   [OK] Test client created")

print("\n7. Testing /health endpoint...")
r = client.get("/health")
print(f"   [OK] /health returned: {r.status_code}")

print("\n8. Testing /stats endpoint...")
r = client.get("/stats")
print(f"   [OK] /stats returned: {r.status_code}")

print("\n9. Testing /alerts POST (minimal payload)...")
payload = {
    'source_ip': '192.168.1.1',
    'dest_ip': '192.168.1.2',
    'protocol': 'TCP',
    'raw_features': {},
    'run_detection': False,  # Minimal: no detection
}
print(f"   Calling POST /alerts without detection...")
import sys
sys.stdout.flush()
sys.stderr.flush()

r = client.post('/alerts', json=payload)
print(f"   [OK] /alerts returned: {r.status_code}")
print(f"   Response: {r.text[:500]}")

print("\n10. Testing /alerts POST (with detection)...")
payload_with_detection = {
    'source_ip': '192.168.1.1',
    'dest_ip': '192.168.1.2',
    'protocol': 'TCP',
    'raw_features': {'Flow Duration': 1.0, 'Total Fwd Packets': 2.0},
    'run_detection': True,
}
print(f"   Calling POST /alerts WITH detection...")
sys.stdout.flush()
sys.stderr.flush()

try:
    r = client.post('/alerts', json=payload_with_detection)
    print(f"   [OK] /alerts returned: {r.status_code}")
    print(f"   Response length: {len(r.text)}")
    print(f"   Response preview: {r.text[:200]}")
except Exception as e:
    print(f"   [ERROR] {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n[SUCCESS] ALL TESTS PASSED!")
