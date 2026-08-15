#!/usr/bin/env python
"""Debug the alert endpoint in isolation."""
import sys
import traceback

print("=" * 60)
print("Starting debug of alert endpoint...")
print("=" * 60)

try:
    print("\n1. Importing modules...")
    from fastapi.testclient import TestClient
    from backend.app import app
    print("   ✓ Imports successful")
    
    print("\n2. Creating test client...")
    client = TestClient(app)
    print("   ✓ Test client created")
    
    print("\n3. Testing GET routes...")
    for route in ["/health", "/stats"]:
        r = client.get(route)
        print(f"   ✓ {route}: {r.status_code}")
    
    print("\n4. Testing POST /alerts endpoint...")
    payload = {
        'source_ip': '203.0.113.10',
        'dest_ip': '198.51.100.2',
        'protocol': 'TCP',
        'raw_features': {'Flow Duration': 1.0, 'Total Fwd Packets': 2.0},
        'run_detection': True,
    }
    print(f"   Payload: {payload}")
    print("   About to call POST /alerts...")
    
    r = client.post('/alerts', json=payload)
    print(f"   ✓ POST /alerts returned: {r.status_code}")
    print(f"   Response: {r.text[:500]}")
    
    if r.status_code == 200:
        print("\n✅ ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print(f"\n❌ Unexpected status code: {r.status_code}")
        sys.exit(1)
        
except Exception as e:
    print(f"\n❌ Error: {type(e).__name__}: {e}")
    traceback.print_exc()
    sys.exit(1)
