# AegisAI Local Setup and Safe Testing Guide

This guide covers the Windows local-development setup, password changes, startup,
feature checks, and an authorized second-computer connectivity check. Docker is
not covered. AegisAI is a local prototype; passing these checks does not qualify
the current model for production use.

## 1. Before you start

You need:

- Windows PowerShell.
- Python 3.12 (the CI-tested version; other versions are not currently validated).
- Node.js 20.19 or newer, or 22.12 or newer, plus npm.
- The project files in `C:\Users\vadit\Desktop\AegisAI`.
- Npcap only if you intend to use live packet capture on Windows.

No external API keys are required for the local app, offline Copilot, automated
tests, or safe simulations. Webhook, Telegram, and SMTP settings are optional.

**Replace any password that has been shown, pasted, or otherwise exposed.**
Choose a new, unique admin password and viewer password. Each must be 12-72
UTF-8 bytes, and the two must differ. Never paste passwords, `.env` contents,
access tokens, or database hashes into chat, screenshots, logs, or source
control.

## 2. Configure `.env`

Open PowerShell in the repository:

```powershell
Set-Location C:\Users\vadit\Desktop\AegisAI
```

Create `.env` from the example only if it does not already exist. Do not
overwrite an existing `.env`:

```powershell
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
}
notepad .env
```

Set these values in `.env`:

- `SECRET_KEY`: a private random value of at least 32 bytes.
- `AEGIS_ADMIN_USERNAME` and `AEGIS_VIEWER_USERNAME`: distinct usernames.
- `AEGIS_ADMIN_PASSWORD` and `AEGIS_VIEWER_PASSWORD`: distinct passwords,
  each 12-72 bytes, not example placeholders.

Keep the `.env` file private and do not commit it. The example webhook,
Telegram, and SMTP values can remain blank unless you intentionally configure
those integrations.

Validate the local configuration without printing its values:

```powershell
.\.venv\Scripts\python.exe -c "from dotenv import load_dotenv; load_dotenv('.env', override=True); from backend.auth import validate_security_config; validate_security_config(); print('Configuration OK')"
```

If PowerShell says the virtual-environment Python does not exist, create the
environment and install dependencies as described in the next section first.
If validation fails, read the named setting in `.env` and check its requirements;
do not print the value to troubleshoot it.

### Change passwords for existing database accounts

The configured passwords are used to create bootstrap accounts once. Editing
`.env` does not replace a password hash for an account already stored in the
database. After changing `.env`, stop the backend and run the following from the
repository root. It synchronizes the configured admin and viewer passwords to
the local database without displaying either password:

```powershell
@'
from dotenv import load_dotenv
load_dotenv(".env", override=True)

import os
from backend.auth import (
    ensure_bootstrap_users,
    get_password_hash,
    validate_security_config,
)
from database.init_db import SessionLocal
from database.models import User

validate_security_config()
ensure_bootstrap_users()
accounts = (
    (os.getenv("AEGIS_ADMIN_USERNAME", "admin"), os.environ["AEGIS_ADMIN_PASSWORD"]),
    (os.getenv("AEGIS_VIEWER_USERNAME", "viewer"), os.environ["AEGIS_VIEWER_PASSWORD"]),
)

db = SessionLocal()
try:
    for username, password in accounts:
        user = db.query(User).filter(User.username == username).one_or_none()
        if user is None:
            raise RuntimeError(f"Configured account was not created: {username}")
        user.hashed_password = get_password_hash(password)
    db.commit()
    print("Configured local account passwords updated.")
finally:
    db.close()
'@ | .\.venv\Scripts\python.exe -
```

This script changes only the two configured account password hashes. Do not run
it with passwords copied from a public example or chat. Sign in using the
configured usernames and the new passwords.

## 3. Install dependencies, build, and initialize

Run this once for a fresh checkout, or when dependencies change:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm --prefix frontend ci
```

Type-check and build the React console:

```powershell
npm --prefix frontend test
npm --prefix frontend run build
```

Initialize or upgrade the local SQLite database:

```powershell
.\.venv\Scripts\python.exe database\init_db.py
```

Do not delete `database\aegisai.db` to solve a login problem; that file contains
user accounts and application records. Use the password synchronization steps
above instead.

## 4. Start the app

Keep the backend running in its own PowerShell window:

```powershell
Set-Location C:\Users\vadit\Desktop\AegisAI
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Do not close that window while using the app. In another PowerShell window,
check that the backend is listening and healthy:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
Get-NetTCPConnection -LocalPort 8000 -State Listen
```

Expected health response includes `"status": "ok"`. If the health request is
refused, the backend is not running; inspect the backend window for its startup
error. If startup reports an invalid setting, correct `.env`, validate again,
then restart.

Open these local pages:

- `http://127.0.0.1:8000/` — public AegisAI homepage.
- `http://127.0.0.1:8000/signin` — Jinja sign-in page used by the homepage.
- `http://127.0.0.1:8000/dashboard` — Jinja live-operations dashboard.
- `http://127.0.0.1:8000/legacy` — compatibility alias for that dashboard.
- `http://127.0.0.1:8000/console` — separate React/Vite console with its own
  sign-in screen; run `npm --prefix frontend run build` first.
- `http://127.0.0.1:8000/api/docs` — API reference.

The homepage is not the sign-in page. Its links take you through the Jinja
sign-in/dashboard flow. The React console is a separate interface at `/console`.

## 5. Safe feature checks

Sign in locally, then try these workflows:

1. **Overview:** check capture status. Without capture, this should show the
   sensor as stopped and counters should remain idle.
2. **Safe sample replay:** use the admin replay control if available. The
   samples are simulated; they do not send packets, persist real alerts, or
   validate live capture.
3. **Attack Lab:** run a packet-free simulation. Its output demonstrates
   simulation logic, not the live model's detection accuracy.
4. **Response Center:** preview policies and inspect dry-run or approval
   behavior. Live firewall enforcement is disabled.
5. **Copilot:** ask a question grounded in the local knowledge base. It works
   offline and does not require an external LLM API key. Admin-ingested content
   is in memory and clears when the server restarts.
6. **Threat Intel:** use the local feed workflow. External feeds and Botnet
   indicators are not automatically populated.
7. **Alerts, Incidents, Reports:** these depend on persisted records. Simulated
   replay may not create records for these pages.
8. **Model Health:** inspect the active model status, but do not interpret a
   loaded model as an accurate or production-qualified model.

For a separate command-line demonstration that changes no network state:

```powershell
.\.venv\Scripts\python.exe scripts\demo_scenario.py
```

It prints simulated events and a report. It does not exercise packet capture.

Run automated checks from the repository root:

```powershell
$env:PYTHONPATH = "."
.\.venv\Scripts\python.exe -m pytest -q
npm --prefix frontend test
npm --prefix frontend run build
```

## 6. Optional local live-capture check

Live capture is optional. On Windows it requires Npcap and may require starting
PowerShell as Administrator. Do not use this as an attack test.

1. Start the backend locally as above. If capture reports a permissions or
   provider error, confirm Npcap is installed and restart the backend in an
   elevated PowerShell window.
2. Sign in locally as admin and open Overview.
3. Select the active interface (for example, Wi-Fi), use the ordinary `ip`
   capture filter, and start capture.
4. Observe packet and flow counters during ordinary use of the computer.
5. Stop capture from the UI.

This confirms only that packets and flows can be observed. It does not prove
that a flow was classified correctly, persisted as an alert, or handled
accurately. Do not run scans, floods, exploit attempts, or password attempts on
your network for this check.

The live rules include bounded indicators for TCP SYN and UDP/ICMP packet-rate
surges, TCP SYN and UDP multi-port scanning, repeated connections to
authentication services, repeated HTTP login requests, high HTTP request
volume, multiple long-lived incomplete cleartext HTTP headers, selected
cleartext HTTP signatures, regular repeated connections, and configured
threat-intelligence matches. These indicate observable patterns, not confirmed
attack intent or service impact. A regular connection can be benign, an
authentication connection does not prove a failed login, encrypted HTTPS
content cannot be inspected by the cleartext rules, and a beacon indicator is
not proof of a botnet. IOC detection works only for configured indicators.

Run the bounded, in-memory packet-rule checks without sending network traffic:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_live_rules.py tests\test_port_scan.py tests\test_live_extractor.py
```

These synthetic packet tests verify that specific rule conditions emit events
and selected ordinary traffic does not cross the tested thresholds. They do
not establish live packet capture, real attack detection, general false-alarm
rates, or guaranteed detection of all variants. Rule events intentionally have
no model-confidence probability; they carry an indicator, evidence, and a
coarse severity. The Random Forest score is also uncalibrated. The latest
source-group-held-out evaluation failed the project's attack-class and benign
false-alarm gates, so treat all detections as experimental and do not enable
autonomous blocking.

## 7. Optional second-computer connectivity check

This procedure checks whether the AegisAI computer can see a harmless HTTP
health request from one other authorized computer. It does **not** create an
attack and does **not** test attack-detection accuracy. Do not expose this
development server on a public or untrusted network.

### On the AegisAI computer

1. Use a private network you own or are authorized to administer. Do not
   continue if Windows reports the connected network as Public.
2. Find the AegisAI computer's private IPv4 address:

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike '127.*' -and $_.AddressState -eq 'Preferred' } |
       Select-Object InterfaceAlias, IPAddress
   ```

3. Find the other test computer's private IPv4 address on that computer.
   Record both addresses locally; do not post them publicly.
4. In an **Administrator PowerShell** on the AegisAI computer, set the two
   addresses below to the actual addresses. This rule allows TCP port 8000 only
   from that one remote IP, to the AegisAI host IP, on the Private profile:

   ```powershell
   $aegisIp = "192.168.1.20"   # replace with AegisAI computer's private IPv4
   $testPcIp = "192.168.1.30"  # replace with the authorized test computer's IPv4
   New-NetFirewallRule `
       -DisplayName "AegisAI one-PC connectivity check" `
       -Direction Inbound `
       -Action Allow `
       -Protocol TCP `
       -LocalAddress $aegisIp `
       -LocalPort 8000 `
       -RemoteAddress $testPcIp `
       -Profile Private
   ```

5. If Uvicorn is already running with `--host 127.0.0.1`, stop it with
   `Ctrl+C`; that setting accepts connections only from the AegisAI computer.
   Then start Uvicorn bound to network interfaces in the backend PowerShell:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
   ```

6. Sign in to AegisAI **from the AegisAI computer itself** at
   `http://127.0.0.1:8000/signin`. Do not send a password over the LAN: this
   development server uses HTTP, not HTTPS.
7. Start capture on the Wi-Fi interface. Set the capture filter to the two
   authorized host addresses and the app's TCP port, replacing both examples:

   ```text
   host 192.168.1.20 and host 192.168.1.30 and tcp port 8000
   ```

   This limits capture to traffic between those two hosts on the test
   connection. If the filter is rejected or no packets are observed, stop the
   test rather than broadening the filter on a shared network.

### On the authorized test computer

Make only this harmless GET request. Replace the sample address with the
AegisAI computer's actual private IPv4 address. Do not type the angle-bracket
placeholder literally; the `$aegisIp` variable below must contain an address
such as `192.168.1.20`:

```powershell
$aegisIp = "192.168.1.20"  # replace with the AegisAI computer's actual private IPv4
Invoke-RestMethod -Uri "http://${aegisIp}:8000/api/v1/health" -Method Get
```

The expected response reports API health. This endpoint requires no login and
the request does not intentionally send credentials or attack traffic.

### Finish and clean up

1. Confirm counters increase on the AegisAI Overview. Allow a few seconds for
   the flow to close or stop capture to flush pending flows.
2. Stop capture in the UI.
3. Stop Uvicorn with `Ctrl+C`.
4. Remove the temporary firewall rule in Administrator PowerShell:

   ```powershell
   Remove-NetFirewallRule -DisplayName "AegisAI one-PC connectivity check"
   ```

5. Confirm the rule is gone:

   ```powershell
   Get-NetFirewallRule -DisplayName "AegisAI one-PC connectivity check" -ErrorAction SilentlyContinue
   ```

Do not sign into the app from the second computer over HTTP. Do not use this
procedure to scan, stress, flood, brute-force, or probe either computer or any
other network device.

## 8. Understanding what a successful check means

- Homepage loads: FastAPI served the public page.
- Health endpoint responds: the API process is reachable.
- Counters rise during capture: the sensor observed packets and emitted flows.
- UI safe replay or Attack Lab runs: a simulated workflow executed.
- Pytest/frontend checks pass: the tested code paths passed automated tests.

None of these, alone or together, establishes that live attack detection is
accurate. The current grouped model evaluation is not release-qualified; see
[`artifacts/strict_group_evaluation.json`](../artifacts/strict_group_evaluation.json)
and [`docs/PROJECT_COMPLETION_PLAN.md`](PROJECT_COMPLETION_PLAN.md) for the
current release blockers and limits.
