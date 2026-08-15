import traceback
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)
payload = {
    'source_ip': '203.0.113.10',
    'dest_ip': '198.51.100.2',
    'protocol': 'TCP',
    'raw_features': {'Flow Duration': 1.0, 'Total Fwd Packets': 2.0},
    'run_detection': True,
}

print('before post')
try:
    resp = client.post('/alerts', json=payload)
    print('status', resp.status_code)
    print('resp', resp.text)
except Exception as e:
    print('EXCEPTION', type(e), e)
    traceback.print_exc()
    raise
print('after post')
