import urllib.request
import urllib.parse
import json

# Test OPTIONS preflight from http://127.0.0.1:5173
req = urllib.request.Request(
    'http://localhost:8000/api/v1/auth/token',
    headers={
        'Origin': 'http://127.0.0.1:5173',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
    },
    method='OPTIONS'
)
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        print('OPTIONS status:', r.status)
        print('OPTIONS headers:', dict(r.headers))
except Exception as e:
    print('OPTIONS error:', e)

# Test POST with boundary
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
lines = [
    f'--{boundary}',
    'Content-Disposition: form-data; name="username"',
    '',
    'admin',
    f'--{boundary}',
    'Content-Disposition: form-data; name="password"',
    '',
    'aegisai2024',
    f'--{boundary}--',
    ''
]
body = '\r\n'.join(lines).encode('utf-8')

req2 = urllib.request.Request(
    'http://localhost:8000/api/v1/auth/token',
    data=body,
    headers={
        'Origin': 'http://127.0.0.1:5173',
        'Content-Type': f'multipart/form-data; boundary={boundary}',
    },
    method='POST'
)
try:
    with urllib.request.urlopen(req2, timeout=5) as r:
        print('POST status:', r.status)
        print('POST body:', r.read().decode())
except Exception as e:
    print('POST error:', e)
