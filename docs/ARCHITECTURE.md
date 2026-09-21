# TRUST System Architecture & Threat Model

## 1. Overview
**TRUST (Terminal Risk & Unseen Signal Tracker)** is an in-browser, zero-installation, privacy-first security analysis engine engineered for untrusted public terminals (cyber cafés, shared kiosks, library computers, and exam terminals).

Before a user enters banking credentials or sensitive passwords, TRUST performs a non-invasive, multi-signal diagnostic across browser-observable execution pipelines in under 3 seconds, returning a composite **Trust Score (0–100)**, traffic-light risk tier, and explainable findings.

---

## 2. Threat Model & Vectors Analyzed

| Threat Vector | Kiosk Real-World Scenario | TRUST Detection Mechanism | Weight |
|---|---|---|---|
| **Keystroke Logging & Hooks** | Malicious extension or user-script overrides `addEventListener` to capture passwords. | Prototype inspection of `EventTarget.prototype.addEventListener`, descriptor checking, `isTrusted` verification. | 25% |
| **Phishing / Clickjacking Overlays** | Hidden transparent fullscreen `<div>` or `<iframe>` capturing input or redirecting clicks. | Viewport geometry scan, z-index inspection (`z-index > 1000`), opacity thresholding (`opacity < 0.1`). | 25% |
| **Clipboard Hijacking / Swappers** | Malware monitoring clipboard to replace crypto addresses or bank IFSC/account numbers. | Cryptographic canary token roundtrip test and `navigator.clipboard` prototype validation. | 20% |
| **Headless / Remote Automation** | Terminal running under remote Selenium, Puppeteer, or automated screen scraping. | `navigator.webdriver` check, headless property inspection, platform vs User-Agent cross-verification. | 15% |
| **Canvas / GPU Fingerprint Tampering** | Spyware or rogue extension injecting dynamic noise into canvas graphics. | Bitwise multi-pass canvas rendering test, WebGL `UNMASKED_RENDERER_WEBGL` hardware GPU inspection. | 10% |
| **Network & Transport Tampering** | Unencrypted HTTP transport or captive portal proxy MITM. | `window.isSecureContext` check, multi-probe RTT jitter, WebRTC STUN candidate leak inspection. | 5% |

---

## 3. Weighted Scoring Mathematics

Composite Trust Score $S$ is computed as:

$$S = \max\left(0, \min\left(100, \frac{\sum_{i=1}^{n} w_i \cdot s_i}{\sum_{i=1}^{n} w_i}\right)\right)$$

Where:
- $w_i$ = Weight assigned to subsystem $i$ (e.g., Input Timing = 25, DOM Integrity = 25, Clipboard = 20)
- $s_i$ = Score of subsystem $i$ ($100 - \sum \text{penalties}$)

### Critical Security Floor Hard Cap
If any **Critical Security Failure** is triggered (e.g. `EventTarget.prototype.addEventListener` overridden by custom non-native code, or clipboard canary mutated in real time), the score is hard-capped at **$\le 55$**, forcing an immediate **HIGH RISK / RED ALERT** regardless of other subsystems.

### Concurrent Attack Load
When the Threat Simulator has active attack paths, TRUST applies a progressive load penalty after the detector score and critical cap:

$$L(A) = \min(100, 2A(A+1))$$

where $A$ is the number of active simulated attacks. The final score is:

$$S_{final} = \max(0, S - L(A))$$

This ensures that a terminal with multiple simultaneous attack paths scores lower than the same terminal with only one active attack. The detector findings remain the explainable evidence; the load penalty models the compounding risk of concurrent threats.

---

## 4. Subsystems Breakdown

```
TRUST Architecture
├── Client-Side Engine (Vanilla JS / Web APIs)
│   ├── Detectors
│   │   ├── inputTiming.js      (Synthetic events, cadence variance, listener hooks)
│   │   ├── clipboard.js        (Canary token R/W, address swapper trap)
│   │   ├── domScript.js        (Prototype tampering, overlay/iframe scanner)
│   │   ├── browserEnv.js       (Webdriver, headless, UA consistency, devtools)
│   │   ├── canvasWebgl.js      (2D canvas noise test, WebGL GPU rasterizer)
│   │   ├── networkSignals.js   (RTT jitter, WebRTC STUN ICE leak)
│   │   └── environment.js      (Timezone/Intl alignment, geometry isolation)
│   ├── Scoring & Explainability (scoring.js)
│   ├── Biometric Dynamics Sandbox (biometricSandbox.js)
│   ├── Threat Simulator (simulator.js)
│   ├── Multi-Language i18n (i18n.js)
│   ├── Offline QR Generator (qrcode.js)
│   └── Report & Wiper (reportExporter.js)
└── Optional Backend (server.py)
    ├── Static File Hosting
    ├── Fleet Telemetry Aggregator (/api/telemetry)
    └── Standalone Bundle Exporter (/download)
```
