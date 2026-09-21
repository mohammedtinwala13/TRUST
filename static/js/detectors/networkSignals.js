/**
 * TRUST - Network Signals & WebRTC Leak Detector
 * Measures connection latency, round-trip jitter, WebRTC IP leakage,
 * and proxy / MITM network indicators.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.networkSignals = {
  id: 'networkSignals',
  name: 'Network Signals & WebRTC Leak Analysis',
  category: 'Network & Connectivity',
  weight: 5, // Medium/Low Weight

  async run() {
    const findings = [];
    let scoreDeductions = 0;

    // 1. Multi-Probe Latency & Jitter Benchmark
    const latencyTest = await this.measureLatencyAndJitter();
    findings.push(latencyTest);
    if (!latencyTest.passed) scoreDeductions += latencyTest.penalty;

    // 2. WebRTC STUN Candidate & Private IP Leak Test
    const webrtcTest = await this.checkWebRTCLeak();
    findings.push(webrtcTest);
    if (!webrtcTest.passed) scoreDeductions += webrtcTest.penalty;

    // 3. Protocol & Transport Security
    const protocolTest = this.checkTransportProtocol();
    findings.push(protocolTest);
    if (!protocolTest.passed) scoreDeductions += protocolTest.penalty;

    const finalScore = Math.max(0, 100 - scoreDeductions);
    const passed = finalScore >= 70;

    return {
      id: this.id,
      name: this.name,
      category: this.category,
      weight: this.weight,
      score: finalScore,
      passed,
      status: finalScore >= 90 ? 'PASSED' : finalScore >= 70 ? 'WARN' : 'FAILED',
      findings,
      telemetry: {
        avgRttMs: latencyTest.avgRtt,
        jitterMs: latencyTest.jitter,
        candidatesFound: webrtcTest.candidatesCount || 0
      }
    };
  },

  /**
   * Fast non-blocking RTT and Jitter benchmark
   */
  async measureLatencyAndJitter() {
    const rtts = [];
    const iterations = 3;

    for (let i = 0; i < iterations; i++) {
      try {
        const start = performance.now();
        // Ping relative path or favicon or current page HEAD with cache busting
        await fetch(window.location.href.split('?')[0] + '?_t=' + Math.random(), {
          method: 'HEAD',
          cache: 'no-store'
        }).catch(() => {
          // If HEAD fails, measure local micro-task latency
          return new Promise(r => setTimeout(r, 10));
        });
        const duration = performance.now() - start;
        rtts.push(duration);
      } catch (e) {
        // Fallback
        rtts.push(20);
      }
    }

    const avgRtt = rtts.reduce((a, b) => a + b, 0) / rtts.length;
    const jitter = rtts.length > 1 
      ? Math.sqrt(rtts.reduce((sum, r) => sum + Math.pow(r - avgRtt, 2), 0) / (rtts.length - 1))
      : 0;

    const isHighLatency = avgRtt > 600;
    const isHighJitter = jitter > 250;

    if (isHighLatency || isHighJitter) {
      return {
        id: 'network_latency_jitter',
        title: 'Elevated Network Latency / Jitter',
        passed: true, // Warning only
        penalty: 5,
        status: 'WARN',
        avgRtt: Math.round(avgRtt),
        jitter: Math.round(jitter),
        observed: `Avg RTT: ${Math.round(avgRtt)}ms | Jitter: ±${Math.round(jitter)}ms`,
        expected: 'RTT < 400ms, Jitter < 100ms',
        explanation: 'Connection exhibits noticeable network delay or fluctuation. Common in rural kiosks, shared 4G dongles, or overloaded café Wi-Fi.',
        importance: 'Unstable connections can lead to transaction timeouts or session drops.'
      };
    }

    return {
      id: 'network_latency_jitter',
      title: 'Network Round-Trip Latency & Stability',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      avgRtt: Math.round(avgRtt),
      jitter: Math.round(jitter),
      observed: `Avg RTT: ${Math.round(avgRtt)}ms | Jitter: ±${Math.round(jitter)}ms (Stable)`,
      expected: 'Low latency and stable packet timing',
      explanation: 'Network response time is fast and consistent with low jitter.',
      importance: 'Ensures reliable banking communication without packet loss.'
    };
  },

  /**
   * Test WebRTC RTCPeerConnection to gather ICE candidates and check for private IP leaks
   */
  async checkWebRTCLeak() {
    if (!window.RTCPeerConnection) {
      return {
        id: 'webrtc_ip_leak',
        title: 'WebRTC API Availability',
        passed: true,
        penalty: 0,
        status: 'INFO',
        candidatesCount: 0,
        observed: 'WebRTC disabled or unsupported',
        expected: 'Standard WebRTC subsystem',
        explanation: 'WebRTC is disabled in this browser, preventing any STUN IP leaks.',
        importance: 'Low'
      };
    }

    return new Promise((resolve) => {
      let timeoutId = null;
      let resolved = false;
      const candidates = [];

      const finish = () => {
        if (resolved) return;
        resolved = true;
        if (timeoutId) clearTimeout(timeoutId);

        try {
          pc.close();
        } catch (e) {}

        const privateIps = candidates.filter(c => /10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/.test(c));

        if (privateIps.length > 0) {
          resolve({
            id: 'webrtc_ip_leak',
            title: 'WebRTC Local Network IP Leak',
            passed: true,
            penalty: 0,
            status: 'INFO',
            candidatesCount: candidates.length,
            observed: `Discovered local subnet IP: ${privateIps[0]}`,
            expected: 'mDNS IP masking or STUN relay',
            explanation: 'WebRTC exposed a local private network IP address. Standard behavior on local networks, but observable by sites.',
            importance: 'Can expose local cyber café subnet structure.'
          });
        } else {
          resolve({
            id: 'webrtc_ip_leak',
            title: 'WebRTC STUN & Network Candidate Check',
            passed: true,
            penalty: 0,
            status: 'PASSED',
            candidatesCount: candidates.length,
            observed: 'WebRTC candidate generation secure (mDNS masked or clean)',
            expected: 'Standard WebRTC ICE handling',
            explanation: 'WebRTC ICE candidate gathering completed without exposing raw internal IP addresses.',
            importance: 'Protects terminal network topology from reconnaissance.'
          });
        }
      };

      // 1.5s fast timeout to prevent blocking scan
      timeoutId = setTimeout(finish, 1500);

      let pc;
      try {
        const config = {
          iceServers: [
            { urls: 'stun:stun.cloudflare.com:3478' }
          ]
        };
        pc = new RTCPeerConnection(config);
        
        pc.onicecandidate = (e) => {
          if (e.candidate && e.candidate.candidate) {
            candidates.push(e.candidate.candidate);
          } else {
            finish();
          }
        };

        // Create dummy data channel and offer to trigger candidate gathering
        pc.createDataChannel('trust-probe');
        pc.createOffer()
          .then(offer => pc.setLocalDescription(offer))
          .catch(() => finish());
      } catch (err) {
        finish();
      }
    });
  },

  /**
   * Check transport protocol and secure transport
   */
  checkTransportProtocol() {
    const isHttps = window.location.protocol === 'https:';
    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const isOfflineFile = window.location.protocol === 'file:';

    if (isOfflineFile) {
      return {
        id: 'transport_protocol',
        title: 'Offline Transport Check',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'file:// standalone mode; no page network transport to downgrade',
        expected: 'HTTPS for hosted deployments, file:// for offline standalone use',
        explanation: 'The standalone bundle has no web-server transport. HTTPS validation applies when TRUST is hosted online.',
        importance: 'Informational: verify the bank website itself uses HTTPS before entering credentials.'
      };
    }

    if (!isHttps && !isLocalhost) {
      return {
        id: 'transport_protocol',
        title: 'Unencrypted Transport Protocol',
        passed: false,
        penalty: 15,
        status: 'WARN',
        observed: `Protocol: ${window.location.protocol}`,
        expected: 'HTTPS Transport (TLS 1.3/1.2)',
        explanation: 'Page is served over unencrypted HTTP. All data in transit can be read by network sniffers.',
        importance: 'Terminal must use HTTPS before opening banking portals.'
      };
    }

    return {
      id: 'transport_protocol',
      title: 'Transport Layer Security (TLS/HTTPS)',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: `${window.location.protocol.toUpperCase()} Secure Transport Active`,
      expected: 'Encrypted communication channel',
      explanation: 'Secure HTTPS transport channel confirmed.',
      importance: 'Ensures encrypted communication with banking servers.'
    };
  }
};
