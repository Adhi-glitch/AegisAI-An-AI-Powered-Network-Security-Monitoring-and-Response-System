#!/usr/bin/env python
import sys
sys.path.insert(0, 'c:\\Users\\vadit\\Desktop\\AegisAI')

from agents.coordinator.coordinator import process_features
import json

features = {"Flow Duration": 1.0, "Total Fwd Packets": 2.0, "source_ip": "203.0.113.10", "dest_ip": "198.51.100.2", "protocol": "TCP"}
result = process_features(features)

print("Result type:", type(result))
print("Result keys:", list(result.keys()) if isinstance(result, dict) else "N/A")

# Try to serialize to JSON
try:
    json_str = json.dumps(result)
    print("JSON serialization successful")
except Exception as e:
    print("JSON serialization failed:", e)
    print("Result:")
    for key, value in result.items():
        print(f"  {key}: {type(value)} = {value}")
