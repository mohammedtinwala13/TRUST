# TRUST API & Detector Reference

## 1. Detector Interface
Every detector in TRUST implements the standardized asynchronous interface:

```javascript
window.TRUST.detectors.detectorName = {
  id: string,          // Unique detector identifier
  name: string,        // Display name
  category: string,    // Category grouping
  weight: number,      // Scoring weight (0-100)
  
  async run(): Promise<{
    id: string,
    name: string,
    category: string,
    weight: number,
    score: number,     // 0 - 100
    passed: boolean,
    status: 'PASSED' | 'WARN' | 'FAILED' | 'INFO',
    findings: Array<Finding>,
    telemetry: Object
  }>
};
```

### Finding Data Contract
```typescript
interface Finding {
  id: string;
  title: string;
  passed: boolean;
  penalty: number;        // Points deducted if failed (e.g. 10 - 40)
  status: 'PASSED' | 'WARN' | 'FAILED' | 'INFO';
  observed: string;       // Human-readable observed telemetry
  expected: string;       // Expected secure baseline
  explanation: string;    // Plain-English explanation
  importance: string;     // Security context / impact
}
```

---

## 2. Subsystem Detectors

### 1. `detectors.inputTiming`
- **`checkSyntheticEventDetection()`**: Tests browser discrimination of `event.isTrusted`.
- **`checkEventListenerInterception()`**: Inspects `EventTarget.prototype.addEventListener` for native `[native code]` signatures and property descriptors.
- **`checkTimestampMonotonicity()`**: Checks microsecond monotonic clock via `performance.now()`.
- **`getCadenceSummary()`**: Analyzes dwell/flight times and variance from interactive typing sandbox.

### 2. `detectors.clipboard`
- **`checkClipboardAPIIntegrity()`**: Inspects `navigator.clipboard` methods for function hooking.
- **`checkClipboardPermissions()`**: Queries clipboard read/write permission status.
- **`runInteractiveCanaryTest()`**: Writes a cryptographic canary (`TRUST-CANARY-...-IFSC-...`) and verifies readback integrity.

### 3. `detectors.domScript`
- **`checkNativePrototypes()`**: Verifies 9 browser primitives (`Function.prototype.toString`, `fetch`, `XHR`, `toDataURL`, etc.).
- **`checkInvisibleOverlays()`**: Scans DOM for fixed/absolute elements covering >70% viewport with `opacity < 0.1` and high z-index.
- **`checkSuspiciousGlobals()`**: Scans window namespace for known scrapers (`__nightmare`, `_phantom`, `cdc_ado...`).

### 4. `detectors.browserEnv`
- **`checkWebdriverFlags()`**: Tests `navigator.webdriver`.
- **`checkHeadlessSignatures()`**: Checks language array length, plugin consistency, window outer dimensions.
- **`checkUAPlatformConsistency()`**: Matches `navigator.userAgent` with `navigator.platform`.

### 5. `detectors.canvasWebgl`
- **`checkCanvasRenderingIntegrity()`**: Performs dual-pass 2D canvas rendering to detect dynamic noise injection extensions.
- **`checkWebGLConsistency()`**: Queries `UNMASKED_RENDERER_WEBGL` to flag software rasterizers (SwiftShader/llvmpipe).

### 6. `detectors.networkSignals`
- **`measureLatencyAndJitter()`**: Calculates multi-probe RTT and standard deviation jitter.
- **`checkWebRTCLeak()`**: Probes RTCPeerConnection STUN candidates for local private IP leaks.

### 7. `detectors.environment`
- **`checkTimezoneLocaleAlignment()`**: Cross-checks `Intl.DateTimeFormat` timezone with `Date().getTimezoneOffset()`.
- **`checkScreenGeometry()`**: Detects iframe kiosk containment (`window.top !== window.self`) and 0x0 display resolutions.
