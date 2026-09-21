/**
 * TRUST - DOM & Script Integrity Detector
 * Scans for prototype tampering, monkey-patched web APIs, phishing overlays,
 * hidden clickjacking frames, and unauthorized kiosk scrapers.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.domScript = {
  id: 'domScript',
  name: 'DOM & Script Integrity Shield',
  category: 'DOM & Scripting',
  weight: 25, // Critical Weight

  async run() {
    const findings = [];
    let scoreDeductions = 0;

    // 1. Native Prototype & Function Hook Verification
    const protoTest = this.checkNativePrototypes();
    findings.push(protoTest);
    if (!protoTest.passed) scoreDeductions += protoTest.penalty;

    // 2. Invisible Phishing Overlay & Clickjacking Scan
    const overlayTest = this.checkInvisibleOverlays();
    findings.push(overlayTest);
    if (!overlayTest.passed) scoreDeductions += overlayTest.penalty;

    // 3. Suspicious Global Variables & Extension Injections
    const globalsTest = this.checkSuspiciousGlobals();
    findings.push(globalsTest);
    if (!globalsTest.passed) scoreDeductions += globalsTest.penalty;

    // 4. Hidden Frames & Iframe Injection Scan
    const iframeTest = this.checkHiddenIframes();
    findings.push(iframeTest);
    if (!iframeTest.passed) scoreDeductions += iframeTest.penalty;

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
        prototypeClean: protoTest.passed,
        overlaysDetected: !overlayTest.passed,
        suspiciousGlobalsCount: globalsTest.detectedList?.length || 0
      }
    };
  },

  /**
   * Verify core browser primitives have not been monkey-patched
   */
  checkNativePrototypes() {
    const primitives = [
      { name: 'Function.prototype.toString', fn: Function.prototype.toString },
      { name: 'EventTarget.prototype.addEventListener', fn: EventTarget.prototype.addEventListener },
      { name: 'EventTarget.prototype.removeEventListener', fn: EventTarget.prototype.removeEventListener },
      { name: 'window.fetch', fn: window.fetch },
      { name: 'window.XMLHttpRequest.prototype.open', fn: window.XMLHttpRequest?.prototype?.open },
      { name: 'HTMLCanvasElement.prototype.toDataURL', fn: HTMLCanvasElement.prototype.toDataURL },
      { name: 'CanvasRenderingContext2D.prototype.getImageData', fn: CanvasRenderingContext2D?.prototype?.getImageData },
      { name: 'Document.prototype.createElement', fn: Document.prototype.createElement },
      { name: 'Storage.prototype.setItem', fn: Storage.prototype.setItem }
    ];

    const tampered = [];

    for (const item of primitives) {
      if (!item.fn) continue;
      try {
        const str = Function.prototype.toString.call(item.fn);
        const isNative = /\{\s*\[native code\]\s*\}/.test(str);
        
        // Also check if function was converted to a simple arrow function or custom closure
        if (!isNative || str.includes('return ') || str.includes('apply(') || str.includes('malware') || str.includes('hook')) {
          tampered.push(item.name);
        }
      } catch (err) {
        tampered.push(`${item.name} (Error: ${err.message})`);
      }
    }

    if (tampered.length === 0) {
      return {
        id: 'native_prototype_integrity',
        title: 'Native API Prototype Integrity',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: `All ${primitives.length} core browser primitives verified native [native code]`,
        expected: 'Untampered native browser primitives',
        explanation: 'Core JavaScript APIs (fetch, addEventListener, toDataURL, XHR) are clean and un-hijacked.',
        importance: 'Malicious scripts and browser extensions often monkey-patch fetch/XHR to steal login requests.'
      };
    } else {
      return {
        id: 'native_prototype_integrity',
        title: 'Native API Monkey-Patching Detected!',
        passed: false,
        penalty: 40,
        status: 'FAILED',
        observed: `Tampered primitives: ${tampered.join(', ')}`,
        expected: 'Standard native code signatures',
        explanation: 'Critical browser APIs have been replaced with custom wrappers. Data interception or network spoofing is active.',
        importance: 'CRITICAL SECURITY BREACH: Passwords and banking requests will be intercepted before reaching the server.'
      };
    }
  },

  /**
   * Scan DOM for invisible phishing overlays, clickjacking traps, and high-z transparent masks
   */
  checkInvisibleOverlays() {
    const suspiciousOverlays = [];
    const elements = document.querySelectorAll('div, section, span, iframe, canvas, form');
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
    const totalArea = viewportWidth * viewportHeight;

    elements.forEach(el => {
      // Skip TRUST's own UI elements
      if (el.closest('#trust-app-container') || el.classList.contains('trust-safe-element') || el.id?.startsWith('trust-')) {
        return;
      }

      try {
        const style = window.getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        const area = rect.width * rect.height;

        const isFixedOrAbs = style.position === 'fixed' || style.position === 'absolute';
        const isHighZ = parseInt(style.zIndex, 10) > 1000;
        const isTransparent = (parseFloat(style.opacity) < 0.1) ||
                              style.visibility === 'hidden' ||
                              style.backgroundColor === 'transparent' ||
                              style.backgroundColor.includes('rgba(0, 0, 0, 0)');
        const interceptsPointerInput = style.pointerEvents !== 'none';

        // A high z-index element is common for legitimate browser chrome,
        // accessibility layers, and modal UI. Flag only an *invisible* layer
        // that also intercepts input; all three conditions are required.
        if (isFixedOrAbs && area > (totalArea * 0.70) && isHighZ && isTransparent && interceptsPointerInput) {
          suspiciousOverlays.push({
            tag: el.tagName,
            id: el.id || 'anonymous',
            className: el.className,
            areaRatio: (area / totalArea).toFixed(2),
            zIndex: style.zIndex,
            opacity: style.opacity
          });
        }
      } catch (e) {
        // Skip un-computable elements
      }
    });

    if (suspiciousOverlays.length === 0) {
      return {
        id: 'overlay_clickjacking_scan',
        title: 'DOM Overlay & Clickjacking Scan',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'No transparent fullscreen overlays or clickjacking masks detected',
        expected: 'Clean viewport layout without deceptive layers',
        explanation: 'The rendered viewport is free from invisible trap layers and clickjacking overlays.',
        importance: 'Deceptive overlays sit above real input boxes to steal clicks and redirect payments.'
      };
    } else {
      return {
        id: 'overlay_clickjacking_scan',
        title: 'Deceptive Fullscreen Overlay Detected!',
        passed: false,
        penalty: 35,
        status: 'FAILED',
        observed: `Found ${suspiciousOverlays.length} suspicious overlay layer(s) covering >70% screen (z-index: ${suspiciousOverlays[0].zIndex}, opacity: ${suspiciousOverlays[0].opacity})`,
        expected: 'No hidden overlay layers',
        explanation: 'An invisible or high z-index overlay is covering the screen! This is a classic signature of phishing or clickjacking.',
        importance: 'HIGH RISK: Your clicks and form entries may be hijacked by a hidden overlay.'
      };
    }
  },

  /**
   * Scan window namespace for known malicious variables, scraper scripts, and automation hooks
   */
  checkSuspiciousGlobals() {
    const knownSignatures = [
      '__nightmare',
      '_phantom',
      'callPhantom',
      '__selenium_evaluate',
      '__webdriver_evaluate',
      '__driver_evaluate',
      '__webdriver_script_function',
      '__webdriver_script_func',
      '__webdriver_script_fn',
      '__fxdriver_evaluate',
      '__driver_unwrapped',
      '__webdriver_unwrapped',
      '__selenium_unwrapped',
      '__fxdriver_unwrapped',
      'Buffer',
      'domAutomation',
      'domAutomationController',
      'cdc_adoQpoasnfa76pfcZLmcfl_Array',
      'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
      'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
      '_carbon',
      'malwareHook',
      'keyloggerActive'
    ];

    const detected = [];
    for (const sig of knownSignatures) {
      if (sig in window) {
        detected.push(sig);
      }
    }

    if (detected.length === 0) {
      return {
        id: 'suspicious_globals_scan',
        title: 'Global Namespace & Extension Scraper Scan',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'Clean global namespace (no automation or scraper artifacts)',
        expected: 'Standard clean browser runtime environment',
        explanation: 'No known kiosk scrapers, automated crawler bridges, or debugger injectors found in the global scope.',
        importance: 'Ensures the page is running in a standard user session rather than an automated scraping harness.'
      };
    } else {
      return {
        id: 'suspicious_globals_scan',
        title: 'Suspicious Automation / Scraper Artifacts Detected',
        passed: false,
        penalty: 30,
        status: 'FAILED',
        detectedList: detected,
        observed: `Detected suspicious global artifacts: ${detected.join(', ')}`,
        expected: 'Zero unauthorized automation variables',
        explanation: 'Found automation frameworks or scraper hooks (e.g. Selenium, Nightmare, Webdriver artifacts) in browser memory.',
        importance: 'HIGH RISK: Terminal session may be monitored or recorded by automated screen/data capture software.'
      };
    }
  },

  /**
   * Check for hidden iframes or nested kiosk framing
   */
  checkHiddenIframes() {
    const iframes = document.querySelectorAll('iframe');
    const hiddenIframes = [];

    iframes.forEach(f => {
      // Ignore if part of TRUST app
      if (f.closest('#trust-app-container') || f.id?.startsWith('trust-')) return;

      const style = window.getComputedStyle(f);
      if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0 || f.width === '0' || f.height === '0') {
        hiddenIframes.push(f.src || 'about:blank');
      }
    });

    if (hiddenIframes.length === 0) {
      return {
        id: 'hidden_iframe_scan',
        title: 'Hidden Iframe & Frame Injection Scan',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'No hidden iframes detected in DOM tree',
        expected: 'No covert background framing',
        explanation: 'No hidden or zero-pixel iframe channels found silently transmitting data.',
        importance: 'Hidden iframes can be used for silent cross-site data exfiltration.'
      };
    } else {
      return {
        id: 'hidden_iframe_scan',
        title: 'Hidden Iframe Detected',
        passed: false,
        penalty: 20,
        status: 'FAILED',
        observed: `Found ${hiddenIframes.length} hidden iframe(s)`,
        expected: 'Clean DOM without hidden frames',
        explanation: 'One or more hidden iframes are embedded in the page.',
        importance: 'Potential background data siphon or cross-origin session tracker.'
      };
    }
  }
};
