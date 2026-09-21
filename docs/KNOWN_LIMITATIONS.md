# TRUST Known Security Limitations & Boundaries

## 1. Transparency & Honesty Policy
TRUST is designed as a **pre-flight risk estimation layer**, answering:
*"Before I type my password, can I trust this browser and terminal environment?"*

**It is NOT an antivirus, rootkit scanner, or guarantee of absolute malware absence.**

---

## 2. Explicit Security Boundaries

### 1. OS-Level Keyloggers & Kernel Rootkits
- **Limitation:** Standard web browsers operate inside a strict security sandbox and cannot read kernel memory, inspect Windows API hooks (e.g. `SetWindowsHookEx`), or inspect USB hardware drivers.
- **Mitigation:** TRUST prompts the user to use the bank's on-screen virtual keyboard and inspect physical USB cables.

### 2. Physical Hardware Skimmers & Video Surveillance
- **Limitation:** Web browsers cannot detect physical video cameras (shoulder surfing) or physical hardware keyloggers plugged inline between keyboard and USB port.
- **Mitigation:** TRUST incorporates a mandatory step in the Safe Banking Protocol prompting manual inspection.

### 3. Hardware Latency vs Malicious Delay
- **Limitation:** Low-spec hardware (older Celeron/Pentium chips in rural cyber cafés) may produce natural micro-delays that mimic timing jitter.
- **Mitigation:** TRUST weights biometric variance over raw latency and categorizes hardware rasterizer fallbacks as low-penalty warnings rather than hard failures.

### 4. Advanced In-Browser Malware with Sandbox Emulation
- **Limitation:** Sophisticated malware designed specifically to bypass TRUST could theoretically forge native code strings (`Function.prototype.toString = () => "function () { [native code] }"`) if loaded before TRUST.
- **Mitigation:** TRUST inspects descriptor flags (`enumerable`, `configurable`), prototype chains, and cross-compares multiple independent subsystem signals.

---

## 3. Summary Guidance for Users
1. **Never enter passwords if TRUST returns HIGH RISK (Score < 70).**
2. **If Score is MEDIUM (70–89), proceed with extreme caution and use on-screen virtual keyboard.**
3. **Always click "Wipe Session & Data" before leaving any public computer.**

## 4. Scan Scope and Activity
- TRUST performs a one-time scan when the page loads or when the user clicks **Rescan**.
- It actively probes browser-visible APIs during that scan, including DOM prototypes, event behavior, canvas/WebGL, storage, environment properties, and selected network/WebRTC behavior.
- It does not inspect Windows processes, kernel memory, installed extensions directly, USB devices, or hardware; it also does not continue monitoring after the scan unless the user starts another scan.
- A standalone `file://` launch is a valid offline deployment. Its transport result is informational because there is no page HTTP transport to secure; this must not lower a clean device's score.
