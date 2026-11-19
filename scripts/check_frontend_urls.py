import re

content = open('frontend/dist/assets/index-BVEVmBNZ.js', encoding='utf-8', errors='ignore').read()

# Search for API base URLs, port references, and ws connections
port_refs = re.findall(r':\d{4}[/"\'\\]', content)
api_refs = re.findall(r'api/v1[/"\'\\][a-z/]{0,30}', content)
ws_refs = re.findall(r'ws[s]?:/[^"\'\\]{3,60}', content)
login_refs = re.findall(r'auth/token[^"\'\\]{0,30}', content)

print("Port references:")
for p in set(port_refs): print(" ", p)

print("\nAPI references (first 10):")
for a in list(set(api_refs))[:10]: print(" ", a)

print("\nWebSocket references:")
for w in set(ws_refs): print(" ", w)

print("\nLogin endpoint references:")
for l in set(login_refs): print(" ", l)
