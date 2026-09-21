# TRUST Deployment Guide

## 1. Zero-Installation Deployment Options

TRUST was engineered to run instantly on low-spec hardware without administrative privileges or software installation.

### Option A: Static Single-File Launch (Offline / USB Flash Drive)
1. Copy `trust-standalone.html` to a USB drive or local disk.
2. Double-click `trust-standalone.html` to open in any web browser (Chrome, Firefox, Edge, Safari, Opera).
3. The scan executes immediately. In standalone file mode, TRUST does not require a server; browser WebRTC and page-probe behavior can still be restricted by the browser. Use hosted HTTPS when transport validation is required.

### Option B: QR Code / Short URL Kiosk Link
1. Host TRUST on an internal or public HTTPS web server (e.g., `https://trust.cybercafe.internal`).
2. Print the TRUST QR code on a laminated card placed next to each cyber café terminal.
3. Users scan the QR code or click the desktop bookmark before beginning their banking session.

### Option C: Lightweight FastAPI Server (Optional Fleet Analytics)
For cyber café owners or kiosk network operators who want aggregated anonymous health metrics:
```bash
# Install dependencies
pip install fastapi uvicorn

# Start the server
python3 server.py
# Server binds to 0.0.0.0:8000
```

---

## 2. Target Environments & Real-World Use Cases

| Target Environment | Key Risks Mitigated | Recommended Workflow |
|---|---|---|
| **Cyber Cafés (India / South Asia)** | Extension scrapers, saved sessions, malicious overlays, network MITM. | Scan via QR code -> Verify Green Score -> Use Incognito -> Click "Wipe Session" when done. |
| **Public Libraries & Exam Centers** | Automated testing harnesses, Selenium background bots, clipboard swappers. | Launch `trust-standalone.html` -> Verify human cadence -> Proceed with exam/form submission. |
| **Airport / Hospital Kiosks** | Screen scraping, session snooping, transparent overlays. | Run 3-second diagnostic -> Verify SSL certificate and hardware integrity. |
| **Shared Co-Working Terminals** | Stale credentials, rogue Chrome extensions, modified browser settings. | Run TRUST scan -> Wipe local storage caches after use. |

---

## 3. Recommended Operator Configuration
For cyber café managers:
- Set `trust-standalone.html` or the hosted TRUST URL as the default browser homepage or desktop shortcut.
- Configure browsers to run in ephemeral/incognito mode between customer sessions.
