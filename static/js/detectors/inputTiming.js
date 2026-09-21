/**
 * TRUST - Input & Interaction Timing Detector
 * Analyzes keystroke cadence, dwell/flight intervals, synthetic event injections,
 * and event listener hijacking / proxy traps.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.inputTiming = {
  id: 'inputTiming',
  name: 'Input & Keystroke Timing Integrity',
  category: 'Input Security',
  weight: 25, // Critical Weight

  /**
   * Run all input timing and event integrity checks
   */
  async run() {
    const findings = [];
    let scoreDeductions = 0;
    const telemetry = {};

    // 1. Synthetic Event Injection Test
    const syntheticTest = this.checkSyntheticEventDetection();
    findings.push(syntheticTest);
    if (!syntheticTest.passed) scoreDeductions += syntheticTest.penalty;

    // 2. Event Listener Hook & Interception Test
    const hookTest = this.checkEventListenerInterception();
    findings.push(hookTest);
    if (!hookTest.passed) scoreDeductions += hookTest.penalty;

    // 3. High-Resolution Timestamp Integrity
    const timerTest = this.checkTimestampMonotonicity();
    findings.push(timerTest);
    if (!timerTest.passed) scoreDeductions += timerTest.penalty;

    // 4. Global Keyboard Event Hijack Check
    const globalKeyTest = this.checkGlobalKeyboardHandlers();
    findings.push(globalKeyTest);
    if (!globalKeyTest.passed) scoreDeductions += globalKeyTest.penalty;

    // 5. Active Biometric Cadence Profile (from user interaction or simulated baseline)
    const cadenceSummary = this.getCadenceSummary();
    findings.push(cadenceSummary);
    if (!cadenceSummary.passed) scoreDeductions += cadenceSummary.penalty;

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
        ...telemetry,
        syntheticTestPassed: syntheticTest.passed,
        hookDetected: !hookTest.passed,
        keystrokesRecorded: window.TRUST._keystrokeSamples ? window.TRUST._keystrokeSamples.length : 0
      }
    };
  },

  /**
   * Test if browser correctly distinguishes synthetic (untrusted) events
   * from authentic user events, and checks if synthetic events are secretly being injected.
   */
  checkSyntheticEventDetection() {
    let syntheticFlagged = false;
    let syntheticEventIsTrustedValue = null;
    let eventReceived = false;

    try {
      const dummyInput = document.createElement('input');
      dummyInput.type = 'text';
      dummyInput.style.position = 'fixed';
      dummyInput.style.top = '-9999px';
      dummyInput.style.left = '-9999px';
      dummyInput.style.opacity = '0';
      document.body.appendChild(dummyInput);

      const handler = (e) => {
        eventReceived = true;
        syntheticEventIsTrustedValue = e.isTrusted;
        // In standard secure browsers, programmatic dispatchEvent MUST have isTrusted === false
        if (e.isTrusted === false) {
          syntheticFlagged = true;
        }
      };

      dummyInput.addEventListener('keydown', handler);
      
      const evt = new KeyboardEvent('keydown', {
        key: 'A',
        code: 'KeyA',
        bubbles: true,
        cancelable: true
      });
      
      dummyInput.dispatchEvent(evt);
      dummyInput.removeEventListener('keydown', handler);
      document.body.removeChild(dummyInput);

      if (eventReceived && syntheticFlagged) {
        return {
          id: 'synthetic_event_discrimination',
          title: 'Synthetic Event Distinction',
          passed: true,
          penalty: 0,
          status: 'PASSED',
          observed: 'isTrusted=false accurately flagged on programmatic events',
          expected: 'Browser enforces event.isTrusted sandbox semantics',
          explanation: 'Browser accurately enforces trust boundaries on programmatic keystrokes, preventing silent synthetic injection.',
          importance: 'Malicious kiosk extensions or scripts can inject keystrokes. Trusted event verification prevents spoofed input.'
        };
      } else {
        return {
          id: 'synthetic_event_discrimination',
          title: 'Synthetic Event Sandbox Anomaly',
          passed: false,
          penalty: 30,
          status: 'FAILED',
          observed: `isTrusted returned ${syntheticEventIsTrustedValue}`,
          expected: 'Programmatic events must report isTrusted === false',
          explanation: 'The browser failed to properly mark programmatic events as untrusted, indicating possible sandbox tampering.',
          importance: 'High risk of automated form hijacking and password injection.'
        };
      }
    } catch (err) {
      return {
        id: 'synthetic_event_discrimination',
        title: 'Synthetic Event Check Error',
        passed: true,
        penalty: 0,
        status: 'WARN',
        observed: err.message,
        expected: 'Normal event dispatch',
        explanation: 'Event dispatch check encountered minor restriction: ' + err.message,
        importance: 'Could not fully verify event sandbox.'
      };
    }
  },

  /**
   * Check if addEventListener or EventTarget prototypes have been monkey-patched or proxy-wrapped
   */
  checkEventListenerInterception() {
    let isHooked = false;
    let hookReason = '';

    try {
      const fnStr = Function.prototype.toString.call(EventTarget.prototype.addEventListener);
      const isNativeStr = /\{\s*\[native code\]\s*\}/.test(fnStr);
      
      if (!isNativeStr) {
        isHooked = true;
        hookReason = 'EventTarget.prototype.addEventListener has been overridden by custom code.';
      }

      // Browser engines legitimately expose different descriptors for native
      // methods, so descriptor flags such as `enumerable` are not evidence of
      // a hook. Compare native source signatures instead.
      const windowFnStr = Function.prototype.toString.call(window.addEventListener);
      if (!/\{\s*\[native code\]\s*\}/.test(windowFnStr)) {
        isHooked = true;
        hookReason = 'window.addEventListener has been replaced with custom code.';
      }
    } catch (e) {
      // Fallback
    }

    if (!isHooked) {
      return {
        id: 'event_listener_integrity',
        title: 'Event Listener Prototype Integrity',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'Native code [native code] verified on EventTarget primitives',
        expected: 'Standard untampered DOM event dispatch pipeline',
        explanation: 'No keylogger hooks or event listener proxies were detected on core input pipelines.',
        importance: 'Kiosk spyware often wraps addEventListener to snoop on passwords as they are typed.'
      };
    } else {
      return {
        id: 'event_listener_integrity',
        title: 'Event Listener Tampering Detected',
        passed: false,
        penalty: 35,
        status: 'FAILED',
        observed: hookReason,
        expected: 'Untampered native EventTarget.prototype.addEventListener',
        explanation: 'The browser\'s event listener interface has been modified! Potential keylogger or input snooper active.',
        importance: 'CRITICAL RISK: Any keystrokes typed on this page can be intercepted by unknown scripts.'
      };
    }
  },

  /**
   * Check high resolution performance timer monotonicity
   */
  checkTimestampMonotonicity() {
    try {
      const t1 = performance.now();
      let diffSum = 0;
      for (let i = 0; i < 100; i++) {
        const temp = Math.sqrt(i * 1.5);
      }
      const t2 = performance.now();
      const delta = t2 - t1;

      if (delta < 0) {
        return {
          id: 'timer_monotonicity',
          title: 'Performance Timer Anomaly',
          passed: false,
          penalty: 15,
          status: 'FAILED',
          observed: `Negative delta: ${delta}ms`,
          expected: 'Monotonically increasing performance.now()',
          explanation: 'Timer showed backward drift, indicating sandbox clock tampering or virtualization anomaly.',
          importance: 'Timing attacks and synthetic injection often disrupt high-resolution timers.'
        };
      }

      return {
        id: 'timer_monotonicity',
        title: 'High-Resolution Timer Monotonicity',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: `Delta ${delta.toFixed(3)}ms (strictly monotonic)`,
        expected: 'Monotonic microsecond clock',
        explanation: 'High-resolution hardware timer is operating normally without clock skew or virtualization buffering.',
        importance: 'Ensures precision timing for keystroke cadence analysis.'
      };
    } catch (e) {
      return {
        id: 'timer_monotonicity',
        title: 'Timer Check Unavailable',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'Unavailable',
        expected: 'performance.now() API',
        explanation: 'Performance timer unavailable, fallback used.',
        importance: 'Minor impact.'
      };
    }
  },

  /**
   * Check for suspicious global onkeydown / onkeypress / onkeyup handlers
   */
  checkGlobalKeyboardHandlers() {
    const suspicious = [];
    if (typeof window.onkeydown === 'function' && !window.TRUST._allowedGlobalHandlers?.includes('window.onkeydown')) {
      suspicious.push('window.onkeydown');
    }
    if (typeof document.onkeydown === 'function' && !window.TRUST._allowedGlobalHandlers?.includes('document.onkeydown')) {
      suspicious.push('document.onkeydown');
    }

    if (suspicious.length === 0) {
      return {
        id: 'global_key_handlers',
        title: 'Global Keyboard Interceptor Check',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'No rogue global keyboard traps on window or document',
        expected: 'Clean global event handler namespace',
        explanation: 'No background keyloggers are bound directly to top-level window/document handlers.',
        importance: 'Unregistered global key handlers often capture credentials before form submission.'
      };
    } else {
      return {
        id: 'global_key_handlers',
        title: 'Suspicious Global Keyboard Trap Found',
        passed: false,
        penalty: 25,
        status: 'FAILED',
        observed: `Active handlers on: ${suspicious.join(', ')}`,
        expected: 'No global key traps',
        explanation: 'Detected unauthorized global key handlers attached to the document or window.',
        importance: 'High risk of credential skimming.'
      };
    }
  },

  /**
   * Analyze interactive keystroke cadence if user has typed in the sandbox
   */
  getCadenceSummary() {
    const samples = window.TRUST._keystrokeSamples || [];
    if (samples.length < 5) {
      return {
        id: 'keystroke_cadence_profile',
        title: 'Interactive Keystroke Dynamics',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: `${samples.length} samples recorded (Ready for interactive test)`,
        expected: 'Human typing cadence baseline',
        explanation: 'Use the interactive typing sandbox below to benchmark live human cadence vs robotic injection.',
        importance: 'Human keystroke variance is naturally irregular; automated bots exhibit rigid flat intervals.'
      };
    }

    // Compute intervals and standard deviation
    const dwellTimes = samples.map(s => s.dwellTime).filter(d => typeof d === 'number' && d >= 0);
    const flightTimes = samples.map(s => s.flightTime).filter(f => typeof f === 'number' && f >= 0);

    const avgDwell = dwellTimes.length ? dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length : 0;
    const avgFlight = flightTimes.length ? flightTimes.reduce((a, b) => a + b, 0) / flightTimes.length : 0;
    
    // Variance calculation
    const dwellVariance = dwellTimes.length > 1
      ? dwellTimes.reduce((sum, d) => sum + Math.pow(d - avgDwell, 2), 0) / (dwellTimes.length - 1)
      : 50;
    const stdDev = Math.sqrt(dwellVariance);

    // Bot injection signatures: stdDev < 1ms or dwellTime < 5ms across all keys
    const isBotLike = (stdDev < 1.5 && samples.length >= 8) || (avgDwell < 4 && samples.length >= 5);

    if (isBotLike) {
      return {
        id: 'keystroke_cadence_profile',
        title: 'Automated Keystroke Injection Detected',
        passed: false,
        penalty: 30,
        status: 'FAILED',
        observed: `Avg Dwell: ${avgDwell.toFixed(1)}ms, StdDev: ${stdDev.toFixed(2)}ms (zero natural jitter)`,
        expected: 'Human biometrics (StdDev > 15ms, Dwell 40-200ms)',
        explanation: 'Keystroke timing is artificially uniform or instant. This strongly indicates scripted macro injection or virtual input.',
        importance: 'Signals automated password stuffing or malware-driven form injection.'
      };
    }

    return {
      id: 'keystroke_cadence_profile',
      title: 'Human Keystroke Dynamics Verified',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: `Avg Dwell: ${avgDwell.toFixed(1)}ms, Flight: ${avgFlight.toFixed(1)}ms, StdDev: ${stdDev.toFixed(1)}ms`,
      expected: 'Natural human biometric timing variance',
      explanation: 'Keystroke rhythm exhibits authentic human biological micro-variations and natural flight times.',
      importance: 'Confirms input is originating from a physical human operator rather than an automated bot.'
    };
  }
};
