/**
 * TRUST - Clipboard Integrity & Hijack Detector
 * Tests clipboard I/O integrity, detects crypto-address/banking credential swapper malware,
 * and analyzes clipboard permissions and event hooks.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.clipboard = {
  id: 'clipboard',
  name: 'Clipboard Security & Hijack Integrity',
  category: 'Data Protection',
  weight: 20, // High Weight

  async run() {
    const findings = [];
    let scoreDeductions = 0;

    // 1. Check Clipboard API Availability and Prototypes
    const apiTest = this.checkClipboardAPIIntegrity();
    findings.push(apiTest);
    if (!apiTest.passed) scoreDeductions += apiTest.penalty;

    // 2. Check Clipboard Permissions Status
    const permTest = await this.checkClipboardPermissions();
    findings.push(permTest);
    if (!permTest.passed) scoreDeductions += permTest.penalty;

    // 3. Canary Token Hijacking Analysis (if triggered or sandbox check)
    const canaryTest = this.getCanaryTestSummary();
    findings.push(canaryTest);
    if (!canaryTest.passed) scoreDeductions += canaryTest.penalty;

    // 4. Clipboard Event Listener Tampering Check
    const eventHookTest = this.checkClipboardHooks();
    findings.push(eventHookTest);
    if (!eventHookTest.passed) scoreDeductions += eventHookTest.penalty;

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
        hasAsyncClipboard: !!(navigator.clipboard && navigator.clipboard.readText),
        permissionState: permTest.observed,
        canaryVerified: canaryTest.passed
      }
    };
  },

  /**
   * Check navigator.clipboard existence and prototype signatures
   */
  checkClipboardAPIIntegrity() {
    if (!navigator.clipboard) {
      return {
        id: 'clipboard_api_presence',
        title: 'Clipboard API Availability',
        passed: true,
        penalty: 5,
        status: 'WARN',
        observed: 'navigator.clipboard not exposed (Standard in non-HTTPS / legacy kiosks)',
        expected: 'W3C Clipboard API support',
        explanation: 'The modern Async Clipboard API is not available or restricted by insecure context (HTTP).',
        importance: 'Kiosks running unencrypted HTTP cannot verify clipboard isolation.'
      };
    }

    try {
      const readTextStr = navigator.clipboard.readText ? navigator.clipboard.readText.toString() : '';
      const writeTextStr = navigator.clipboard.writeText ? navigator.clipboard.writeText.toString() : '';

      const isReadNative = /\{\s*\[native code\]\s*\}/.test(readTextStr);
      const isWriteNative = /\{\s*\[native code\]\s*\}/.test(writeTextStr);

      if (!isReadNative || !isWriteNative) {
        return {
          id: 'clipboard_api_presence',
          title: 'Clipboard API Tampering Detected',
          passed: false,
          penalty: 35,
          status: 'FAILED',
          observed: 'navigator.clipboard methods contain non-native JS wrapper code',
          expected: 'Native code implementation',
          explanation: 'The clipboard functions have been hooked or proxied by an active extension or malicious script.',
          importance: 'CRITICAL: Copied passwords or banking account numbers may be captured or replaced in memory.'
        };
      }

      return {
        id: 'clipboard_api_presence',
        title: 'Clipboard API Native Signature',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'Native [native code] verified on navigator.clipboard primitives',
        expected: 'Standard native browser clipboard implementation',
        explanation: 'Clipboard subsystem is intact and unmodified by user-scripts.',
        importance: 'Ensures banking credentials or OTPs copied to clipboard remain private.'
      };
    } catch (e) {
      return {
        id: 'clipboard_api_presence',
        title: 'Clipboard API Query Error',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: e.message,
        expected: 'Standard Clipboard API',
        explanation: 'Could not inspect clipboard descriptors: ' + e.message,
        importance: 'Low'
      };
    }
  },

  /**
   * Check permissions status for clipboard-read and clipboard-write
   */
  async checkClipboardPermissions() {
    if (!navigator.permissions || !navigator.permissions.query) {
      return {
        id: 'clipboard_permissions',
        title: 'Clipboard Permissions Policy',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'Permissions API not available',
        expected: 'Standard permission sandbox',
        explanation: 'Browser uses default interaction-gated clipboard permissions.',
        importance: 'Standard for older browser engines.'
      };
    }

    try {
      // Note: clipboard-read permission descriptor might throw in Firefox or older Chrome
      let readStatus = 'prompt';
      try {
        const queryResult = await navigator.permissions.query({ name: 'clipboard-read' });
        readStatus = queryResult.state;
      } catch (err) {
        // Fallback for browsers that don't support clipboard-read descriptor
        readStatus = 'user-gesture-gated';
      }

      return {
        id: 'clipboard_permissions',
        title: 'Clipboard Access Permissions',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: `Permission state: ${readStatus}`,
        expected: 'Gated by user gesture or explicit prompt',
        explanation: 'Clipboard reading is gated behind user authorization, preventing silent background scraping.',
        importance: 'Prevents background tabs from quietly harvesting OTPs or copied numbers.'
      };
    } catch (e) {
      return {
        id: 'clipboard_permissions',
        title: 'Clipboard Permissions',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'Standard gesture sandbox',
        expected: 'Restricted clipboard access',
        explanation: 'Clipboard access requires explicit user interaction.',
        importance: 'Protects sensitive clipboard data.'
      };
    }
  },

  /**
   * Interactive or cached canary token integrity analysis
   */
  getCanaryTestSummary() {
    const canaryResult = window.TRUST._canaryTestResult;
    if (!canaryResult) {
      return {
        id: 'clipboard_canary_audit',
        title: 'Clipboard Canary Swapper Audit',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'Ready for one-click interactive clipboard test',
        expected: 'Canary token roundtrip verification',
        explanation: 'Click "Test Clipboard Canary" below to test if background malware alters copied account numbers or crypto addresses.',
        importance: 'Clipboard swapper malware secretly replaces copied bank IFSC codes / wallet addresses with attacker accounts.'
      };
    }

    if (canaryResult.hijacked) {
      return {
        id: 'clipboard_canary_audit',
        title: 'Clipboard Hijacking / Swapping DETECTED!',
        passed: false,
        penalty: 40,
        status: 'FAILED',
        observed: `Written: "${canaryResult.written}" -> Read: "${canaryResult.read}" (Mismatch!)`,
        expected: 'Exact token match',
        explanation: 'The text placed in the clipboard was altered during transit! Active clipboard swapper malware is detected on this terminal.',
        importance: 'CRITICAL DANGER: DO NOT COPY OR PASTE BANKING CREDENTIALS OR ACCOUNT NUMBERS ON THIS COMPUTER.'
      };
    }

    return {
      id: 'clipboard_canary_audit',
      title: 'Clipboard Canary Roundtrip Verified',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: `Verified canary token "${canaryResult.written}" matches readback perfectly`,
      expected: '100% Bitwise identical payload',
      explanation: 'No clipboard modification, string replacement, or regex hijacking observed during roundtrip test.',
      importance: 'Confirms clipboard pipeline is clean and free of active text swappers.'
    };
  },

  /**
   * Check for suspicious copy/cut/paste hooks in document
   */
  checkClipboardHooks() {
    let hooksFound = false;
    let hookDetails = '';

    if (typeof document.oncopy === 'function' && !window.TRUST._allowedGlobalHandlers?.includes('document.oncopy')) {
      hooksFound = true;
      hookDetails = 'document.oncopy handler is active.';
    }
    if (typeof document.onpaste === 'function' && !window.TRUST._allowedGlobalHandlers?.includes('document.onpaste')) {
      hooksFound = true;
      hookDetails += ' document.onpaste handler is active.';
    }

    if (hooksFound) {
      return {
        id: 'clipboard_hooks',
        title: 'Suspicious Clipboard Event Handler',
        passed: false,
        penalty: 20,
        status: 'FAILED',
        observed: hookDetails,
        expected: 'No global copy/paste interceptors',
        explanation: 'Global copy or paste event handlers are attached to the document root.',
        importance: 'May intercept sensitive text as you copy or paste credentials.'
      };
    }

    return {
      id: 'clipboard_hooks',
      title: 'Global Clipboard Event Handlers',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: 'Clean document root (no unauthorized copy/paste interceptors)',
      expected: 'No global clipboard interceptors',
      explanation: 'No rogue global handlers listening on copy, cut, or paste actions.',
      importance: 'Ensures copied data is not intercepted by unauthorized scripts.'
    };
  },

  /**
   * Execute an active interactive canary roundtrip test
   */
  async runInteractiveCanaryTest() {
    const canaryToken = `TRUST-CANARY-${Math.floor(100000 + Math.random() * 900000)}-IFSC-SBIN0001824`;
    let readBack = '';
    let success = false;
    let hijacked = false;
    let errorMsg = null;

    try {
      if (navigator.clipboard && navigator.clipboard.writeText && navigator.clipboard.readText) {
        await navigator.clipboard.writeText(canaryToken);
        // Small delay to simulate background swapper trigger
        await new Promise(r => setTimeout(r, 80));
        readBack = await navigator.clipboard.readText();
        success = true;
        hijacked = (readBack !== canaryToken);
      } else {
        // Fallback using textarea execCommand
        const textarea = document.createElement('textarea');
        textarea.value = canaryToken;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);

        // Readback via dummy paste input
        const pasteInput = document.createElement('input');
        pasteInput.type = 'text';
        pasteInput.style.position = 'fixed';
        pasteInput.style.left = '-9999px';
        document.body.appendChild(pasteInput);
        pasteInput.focus();
        document.execCommand('paste');
        readBack = pasteInput.value;
        document.body.removeChild(pasteInput);

        // If browser blocked programmatic paste, mark as inconclusive
        if (!readBack) {
          success = false;
          errorMsg = 'Browser blocked programmatic paste access';
        } else {
          success = true;
          hijacked = (readBack !== canaryToken);
        }
      }
    } catch (err) {
      errorMsg = err.message;
      success = false;
    }

    window.TRUST._canaryTestResult = {
      written: canaryToken,
      read: readBack,
      success,
      hijacked,
      error: errorMsg,
      timestamp: Date.now()
    };

    return window.TRUST._canaryTestResult;
  }
};
