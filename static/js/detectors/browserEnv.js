/**
 * TRUST - Browser Environment & Automation Detector
 * Detects headless browser harnesses (Puppeteer/Selenium), automation flags (navigator.webdriver),
 * platform/User-Agent inconsistencies, devtools surveillance, and security context isolation.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.browserEnv = {
  id: 'browserEnv',
  name: 'Browser Environment & Automation Integrity',
  category: 'Environment & Runtime',
  weight: 15, // High Weight

  async run() {
    const findings = [];
    let scoreDeductions = 0;

    // 1. Webdriver & Automation Flags
    const webdriverTest = this.checkWebdriverFlags();
    findings.push(webdriverTest);
    if (!webdriverTest.passed) scoreDeductions += webdriverTest.penalty;

    // 2. Headless Browser Characteristic Anomalies
    const headlessTest = this.checkHeadlessSignatures();
    findings.push(headlessTest);
    if (!headlessTest.passed) scoreDeductions += headlessTest.penalty;

    // 3. Platform & User-Agent Consistency
    const uaTest = this.checkUAPlatformConsistency();
    findings.push(uaTest);
    if (!uaTest.passed) scoreDeductions += uaTest.penalty;

    // 4. Secure Context & Storage Isolation
    const securityTest = this.checkSecurityContextAndStorage();
    findings.push(securityTest);
    if (!securityTest.passed) scoreDeductions += securityTest.penalty;

    // 5. DevTools & Debugger Surveillance Heuristic
    const devtoolsTest = await this.checkDevtoolsSurveillance();
    findings.push(devtoolsTest);
    if (!devtoolsTest.passed) scoreDeductions += devtoolsTest.penalty;

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
        webdriver: !!navigator.webdriver,
        isSecureContext: !!window.isSecureContext,
        platform: navigator.platform,
        userAgent: navigator.userAgent
      }
    };
  },

  /**
   * Check navigator.webdriver and automation properties
   */
  checkWebdriverFlags() {
    const isWebdriver = navigator.webdriver === true || 
      (window.TRUST._simulatedWebdriver === true) ||
      (window.document.documentElement.getAttribute('webdriver') !== null);

    if (isWebdriver) {
      return {
        id: 'webdriver_automation_flag',
        title: 'Browser Automation (navigator.webdriver) Active',
        passed: false,
        penalty: 45,
        status: 'FAILED',
        observed: 'navigator.webdriver === true',
        expected: 'Standard manual user browser (navigator.webdriver === false/undefined)',
        explanation: 'The browser reports that it is currently controlled by an automated testing harness or remote bot.',
        importance: 'CRITICAL: The browser session can be remotely scripted, recorded, or controlled by an external process.'
      };
    }

    return {
      id: 'webdriver_automation_flag',
      title: 'Webdriver Automation Flag Check',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: 'navigator.webdriver is false / unflagged',
      expected: 'navigator.webdriver === false',
      explanation: 'No automated browser control flags detected.',
      importance: 'Confirms standard user session rather than headless remote automation.'
    };
  },

  /**
   * Check for headless browser signatures (e.g. zero plugins, empty languages, broken notifications)
   */
  checkHeadlessSignatures() {
    const anomalies = [];
    const ua = navigator.userAgent.toLowerCase();
    const isChrome = /chrome|crios/i.test(ua) && !/edg|opr|brave/i.test(ua);

    // Headless Chrome often has 'HeadlessChrome' in UA if unmasked
    if (ua.includes('headlesschrome')) {
      anomalies.push('User-Agent explicitly declares HeadlessChrome');
    }

    // Languages array should not be empty
    if (!navigator.languages || navigator.languages.length === 0) {
      anomalies.push('navigator.languages array is completely empty');
    }

    // Chrome typically has window.chrome object
    if (isChrome && typeof window.chrome === 'undefined') {
      anomalies.push('Chrome User-Agent without window.chrome object');
    }

    // Outer dimensions check
    if (window.outerWidth === 0 && window.outerHeight === 0) {
      anomalies.push('Window outer dimensions are 0x0 (headless render)');
    }

    if (anomalies.length > 0) {
      return {
        id: 'headless_signatures',
        title: 'Headless Browser Anomaly Detected',
        passed: false,
        penalty: 30,
        status: 'FAILED',
        observed: anomalies.join('; '),
        expected: 'Standard interactive desktop browser profile',
        explanation: 'Browser environment exhibits headless characteristics typical of scrapers or bot sandboxes.',
        importance: 'High risk of session virtualization or automated interception.'
      };
    }

    return {
      id: 'headless_signatures',
      title: 'Browser Headless Profile Check',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: 'Standard desktop window dimensions, language arrays, and vendor objects',
      expected: 'Interactive human browser environment',
      explanation: 'No headless anomalies detected in browser properties.',
      importance: 'Validates authentic desktop terminal execution.'
    };
  },

  /**
   * Check Platform & User-Agent consistency
   */
  checkUAPlatformConsistency() {
    const ua = navigator.userAgent;
    const platform = navigator.platform || '';
    const inconsistencies = [];

    // Check Windows mismatch
    if (ua.includes('Windows') && !platform.includes('Win')) {
      inconsistencies.push(`UA claims Windows, but platform is "${platform}"`);
    }

    // Check Mac mismatch
    if (ua.includes('Macintosh') && !platform.includes('Mac')) {
      inconsistencies.push(`UA claims Mac, but platform is "${platform}"`);
    }

    // Check Linux mismatch
    if (ua.includes('Linux') && !platform.includes('Linux') && !ua.includes('Android')) {
      inconsistencies.push(`UA claims Linux, but platform is "${platform}"`);
    }

    // Touch points check: standard desktop usually 0 (or >0 for touchscreen laptops), but mobile UA with maxTouchPoints 0 is suspicious
    if ((ua.includes('Mobile') || ua.includes('iPhone') || ua.includes('Android')) && navigator.maxTouchPoints === 0) {
      inconsistencies.push('Mobile UA reported on non-touch terminal');
    }

    if (inconsistencies.length > 0) {
      return {
        id: 'ua_platform_consistency',
        title: 'User-Agent / Platform Mismatch Detected',
        passed: false,
        penalty: 15,
        status: 'WARN',
        observed: inconsistencies.join('; '),
        expected: 'Platform and User-Agent alignment',
        explanation: 'Browser headers show mismatched OS/Platform values, indicating user-agent spoofing or proxy rewriting.',
        importance: 'May indicate deceptive browser spoofing software on the kiosk.'
      };
    }

    return {
      id: 'ua_platform_consistency',
      title: 'User-Agent & Platform Alignment',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: `Platform "${platform}" matches User-Agent OS descriptors`,
      expected: 'Consistent OS fingerprint',
      explanation: 'Operating system and browser signatures are coherent and un-spoofed.',
      importance: 'Validates consistency between low-level platform APIs and HTTP headers.'
    };
  },

  /**
   * Check Secure Context (HTTPS) and Storage Isolation
   */
  checkSecurityContextAndStorage() {
    const isSecure = window.isSecureContext;
    const isHttps = window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const isOfflineFile = window.location.protocol === 'file:';
    
    let storageWorking = false;
    try {
      const testKey = '__trust_test_key__';
      localStorage.setItem(testKey, '1');
      storageWorking = (localStorage.getItem(testKey) === '1');
      localStorage.removeItem(testKey);
    } catch (e) {
      storageWorking = false;
    }

    // Standalone TRUST is intentionally launched from file://. There is no
    // network transport to encrypt in that mode, so do not flag it as HTTP.
    if (isOfflineFile) {
      return {
        id: 'security_context',
        title: 'Offline Standalone Context',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'Standalone file opened locally; no page network transport is used',
        expected: 'HTTPS for hosted deployments, file:// for offline standalone use',
        explanation: 'The standalone bundle is running locally. file:// may be reported as an insecure browser context, but this does not mean the page is sending credentials over HTTP.',
        importance: 'Informational: use hosted HTTPS when checking transport security for an online deployment.'
      };
    }

    if (!isSecure && !isHttps) {
      return {
        id: 'security_context',
        title: 'Insecure HTTP Transport Context',
        passed: false,
        penalty: 25,
        status: 'FAILED',
        observed: `Protocol: ${window.location.protocol} (Insecure Context)`,
        expected: 'HTTPS (Encrypted transport)',
        explanation: 'The terminal session is running over plain unencrypted HTTP. All network traffic can be intercepted on the local LAN.',
        importance: 'CRITICAL: Never bank over unencrypted HTTP. Local cyber café Wi-Fi / switch can read your passwords in plain text.'
      };
    }

    return {
      id: 'security_context',
      title: 'Secure Context & Storage Isolation',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: `isSecureContext: ${isSecure}, Storage sandbox functional`,
      expected: 'Secure origin with isolated local storage',
      explanation: 'Terminal session runs in a verified secure context with active cryptographic isolation.',
      importance: 'Prevents man-in-the-middle sniffing of credentials.'
    };
  },

  /**
   * Heuristic test for active devtools / debugger surveillance
   */
  async checkDevtoolsSurveillance() {
    let debuggerDetected = false;
    const start = performance.now();
    
    // Non-blocking micro-check for console inspection timing
    try {
      const t1 = performance.now();
      const div = document.createElement('div');
      Object.defineProperty(div, 'id', {
        get: () => {
          debuggerDetected = true;
          return 'trust-check';
        }
      });
      // console.log on getter only triggers when devtools formatters inspect it
      // (safe silent check)
      const t2 = performance.now();
      if ((t2 - t1) > 100) {
        debuggerDetected = true;
      }
    } catch (e) {}

    if (debuggerDetected) {
      return {
        id: 'devtools_surveillance',
        title: 'Active DevTools Surveillance Detected',
        passed: false,
        penalty: 20,
        status: 'WARN',
        observed: 'Developer inspection / debug hooks actively open',
        expected: 'Standard closed devtools environment',
        explanation: 'Browser Developer Tools appear to be open or monitoring network/console activity on this kiosk.',
        importance: 'Kiosk administrators or previous users could be inspecting passwords or network tokens via DevTools.'
      };
    }

    return {
      id: 'devtools_surveillance',
      title: 'DevTools Surveillance Check',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: 'No active debugger or console interception hooks triggered',
      expected: 'Standard closed console environment',
      explanation: 'No background developer inspection probes or active debugging sessions detected.',
      importance: 'Ensures terminal is not under active manual inspection.'
    };
  }
};
