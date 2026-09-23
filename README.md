# TRUST — Terminal Risk & Unseen Signal Tracker
### Browser-Based Pre-Banking Safety Check for Public & Untrusted Terminals

Live website link - https://mohammedtinwala13.github.io/TRUST/
(hosted on github pages)


[![Live Demo](https://img.shields.io/badge/Demo-Live%20Preview-06b6d4)](http://localhost:8000)
[![Zero Install](https://img.shields.io/badge/Install-Zero%20Install-10b981)](trust-standalone.html)
[![Privacy First](https://img.shields.io/badge/Privacy-100%25%20Local-8b5cf6)]()
[![Tests](https://img.shields.io/badge/Tests-Passing%20(3%2F3)-10b981)]()

---

## 📖 Product Overview

**TRUST (Terminal Risk & Unseen Signal Tracker)** is a browser-only, zero-installation security verification tool that answers one critical question before you enter financial credentials on public computers:

> **"Before I type my password, can I trust this computer?"**

Public kiosks, cyber cafés (in rural/semi-urban South Asia and globally), shared exam centers, and library workstations are frequently plagued by rogue extensions, keylogging user-scripts, clipboard swappers, hidden phishing overlays, and automation bots. 

TRUST runs a comprehensive 7-subsystem heuristic security diagnostic in **under 3 seconds**, generating an explainable **0–100 Trust Score**, traffic-light recommendation, and actionable guidance without requiring software installation or admin rights.

---

## ⚡ Key Highlights

- **Zero Install & No Admin Required:** Runs directly from any modern web browser or offline HTML file.
- **Fast Diagnostic (<3s):** Analyzes 7 browser-observable subsystems concurrently.
- **Explainable Trust Score (0–100):** Clear Green / Yellow / Red traffic light with line-by-line reasoning.
- **Threat Simulation Center:** Built-in attack playground to test keylogger hooks, prototype tampering, phishing overlays, clipboard swappers, and webdriver bots in real time.
- **Interactive Biometric Keystroke Sandbox:** Live keystroke dynamics chart plotting dwell times, flight times, and biological jitter.
- **Clipboard Canary Audit:** One-click verification against clipboard swapper malware.
- **Multi-Language Support (i18n):** English, Hindi (हिंदी), Marathi (मराठी), Spanish (Español), French (Français).
- **Offline Standalone Single-File Bundle (`trust-standalone.html`):** 100% portable, works without internet or external CDNs.
- **Privacy First:** Analysis runs client-side inside the browser sandbox; no sensitive data is sent to a TRUST server. Hosted mode performs local page probes and may attempt browser WebRTC/HTTP probes, subject to browser permissions and policy.

---

## 🛡️ The 7 Browser-Observable Signal Detectors

1. **Input & Interaction Timing (`detectors/inputTiming.js` - Weight 25%):**
   - Detects synthetic / untrusted programmatic keystroke injection (`event.isTrusted === false`).
   - Checks `EventTarget.prototype.addEventListener` for monkey-patched keylogger hooks.
   - Verifies monotonic timer integrity (`performance.now()`).
   - Biometric cadence profiling (dwell/flight variance).

2. **DOM & Script Integrity (`detectors/domScript.js` - Weight 25%):**
   - Verifies native code signatures across 9 critical browser primitives (`fetch`, `XHR`, `toDataURL`, `addEventListener`, etc.).
   - Scans viewport for invisible or transparent clickjacking / phishing overlays (`opacity < 0.1`, `z-index > 1000`).
   - Scans global namespace for scraper and bot frameworks (`__nightmare`, `_phantom`, `cdc_ado...`).
   - Detects hidden background iframe injectors.

3. **Clipboard Integrity & Swapper Trap (`detectors/clipboard.js` - Weight 20%):**
   - Tests `navigator.clipboard` prototype tampering.
   - Interactive Canary Token roundtrip test detecting active clipboard swapper malware (crypto/bank account swappers).
   - Audits global `copy` / `paste` event interceptors.

4. **Browser Environment & Automation (`detectors/browserEnv.js` - Weight 15%):**
   - Inspects `navigator.webdriver` and headless automation flags.
   - Cross-references User-Agent against `navigator.platform` and hardware touch capabilities.
   - Checks `window.isSecureContext` and storage isolation.
   - Heuristic check for active DevTools surveillance.

5. **Canvas & WebGL Consistency (`detectors/canvasWebgl.js` - Weight 10%):**
   - Dual-pass 2D canvas subpixel & emoji rendering test to detect dynamic noise injection / anti-fingerprinting extensions.
   - Queries `UNMASKED_RENDERER_WEBGL` to flag software rasterizers (SwiftShader / llvmpipe) indicating virtualized environments.
   - Checks `toDataURL` prototype integrity.

6. **Network Signals & WebRTC Leak (`detectors/networkSignals.js` - Weight 5%):**
   - Measures multi-probe RTT latency and jitter stability.
   - Probes RTCPeerConnection STUN candidates to detect private subnet IP leaks.
   - Verifies encrypted HTTPS transport.

7. **Environment Characteristics & Geometry (`detectors/environment.js` - Weight 5%):**
   - Aligns `Intl.DateTimeFormat` timezone against system UTC offset.
   - Verifies language headers consistency.
   - Detects nested iframe containment (`window.top !== window.self`) and 0x0 display resolutions.

---

## 🚦 Trust Score & Risk Thresholds

```
  ┌──────────────────────────────────────────────────────────────┐
  │  TRUST SCORE: 90–100  │  LOW RISK (GREEN)                    │
  │  Recommendation: Safe to proceed with banking entry.         │
  ├──────────────────────────────────────────────────────────────┤
  │  TRUST SCORE: 70–89   │  MEDIUM RISK (YELLOW / AMBER)        │
  │  Recommendation: Proceed with heightened caution; use bank's │
  │                  virtual on-screen keyboard.                 │
  ├──────────────────────────────────────────────────────────────┤
  │  TRUST SCORE: 0–69    │  HIGH / CRITICAL RISK (RED)          │
  │  Recommendation: DANGER! DO NOT ENTER PASSWORDS OR BANKING   │
  │                  CREDENTIALS ON THIS TERMINAL.               │
  └──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart & Usage

### Method 1: Instant Standalone (No Server Needed)
Simply open `trust-standalone.html` in any browser:
```bash
# On Linux/macOS
google-chrome trust-standalone.html
# or
firefox trust-standalone.html
```

### Method 2: Launch Local Web Server (FastAPI)
```bash
# Start server on 0.0.0.0:8000
python3 server.py
```
Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## 🧪 Testing & Verification

Run the automated test suite:
```bash
./tests/run_tests.sh
```

Tests include:
1. **Python Scoring Unit Tests (`tests/test_scoring.py`):** Validates clean baselines, critical failure hard caps, and weighted arithmetic.
2. **Node.js Detector & Bundle Tests (`tests/test_detectors.js`):** Validates file existence, standalone bundle completeness, and i18n dictionaries.
3. **Standalone Re-Bundler (`bundle_standalone.py`):** Automatically compiles all modular CSS and JS detectors into `trust-standalone.html`.

---

## 📂 Project Structure

```
.
├── trust-standalone.html       # Zero-dependency, 100% self-contained portable distribution
├── index.html                  # Main Web Dashboard application
├── server.py                   # FastAPI server with static hosting & fleet telemetry
├── bundle_standalone.py        # Automated single-file bundler script
├── generate_zip.py             # Packager script for deliverable ZIP archive
├── trust-security-suite.zip    # Complete pre-packaged distribution archive
├── static/
│   ├── css/
│   │   ├── main.css            # Cyber HUD design system & themes
│   │   ├── components.css      # Gauge dial, radar HUD, threat simulator, biometrics
│   │   └── print.css           # High-contrast printable audit sheet styles
│   │   └── terminal.css        # TRUST Terminal visual template styles
│   └── js/
│       ├── app.js              # Application orchestrator
│       ├── i18n.js             # Internationalization (EN, HI, MR, ES, FR)
│       ├── qrcode.js           # Offline pure-JS SVG QR code generator
│       ├── scoring.js          # Weighted scoring & explainability engine
│       ├── simulator.js        # Threat & attack simulation playground
│       ├── biometricSandbox.js # Biometric typing dynamics analyzer & canvas chart
│       ├── reportExporter.js   # JSON audit exporter, PDF certificate & session wiper
│       └── detectors/
│           ├── inputTiming.js  # Keystroke cadence, dwell/flight, synthetic events
│           ├── clipboard.js    # Clipboard canary roundtrip & swapper detector
│           ├── domScript.js    # Prototype monkey-patching, overlay & iframe scanner
│           ├── browserEnv.js   # Webdriver, headless flags, UA/platform alignment
│           ├── canvasWebgl.js  # 2D canvas noise detector, WebGL GPU verification
│           ├── networkSignals.js # Latency, jitter, WebRTC STUN candidate leak
│           └── environment.js  # Timezone, locale, and screen geometry isolation
├── tests/
│   ├── test_scoring.py         # Python unit tests for scoring engine
│   ├── test_detectors.js       # Node.js detector and integrity tests
│   └── run_tests.sh            # One-click test runner
└── docs/
    ├── ARCHITECTURE.md         # Architecture, threat model & scoring formulas
    ├── DEPLOYMENT_GUIDE.md     # Cyber café, kiosk, exam center deployment guide
    ├── API_REFERENCE.md        # Detector interfaces and data schemas
    └── KNOWN_LIMITATIONS.md    # Transparent security boundaries & mitigations
```

---

## 🔒 Security Disclaimer & Honesty Note

> **"This checks for invisible terminal risk. It does NOT prove malware absence."**

TRUST is an in-browser risk estimation layer designed to detect browser-level tampering, rogue extensions, and proxy overlays during the scan. It cannot inspect kernel OS memory, continuously watch the device, or detect hardware USB keyloggers. Users must follow the included **Safe Banking Protocol** on public computers.

---

## 📄 License
MIT License. Built for public terminal and cyber café security.
