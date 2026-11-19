from pathlib import Path

js_path = Path("frontend/dist/assets/index-BVEVmBNZ.js")
content = js_path.read_text(encoding="utf-8")

target = "var Gc=`http://localhost:8000`"
replacement = "var Gc=window.location.port==='8000'?window.location.origin:`${window.location.protocol}//${window.location.hostname}:8000`"

if target in content:
    content = content.replace(target, replacement, 1)
    js_path.write_text(content, encoding="utf-8")
    print("SUCCESS: Patched Gc in index-BVEVmBNZ.js!")
else:
    print("Checking if already patched...")
    if "window.location.port==='8000'" in content:
        print("Already patched!")
    else:
        print("Target string not found!")
