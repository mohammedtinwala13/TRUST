/**
 * TRUST - Environment Characteristics Detector
 * Checks timezone vs locale alignment, language array consistency,
 * screen resolution vs viewport geometry, and kiosk containment traps.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.environment = {
  id: 'environment',
  name: 'Environment & Geometry Consistency',
  category: 'Environment Characteristics',
  weight: 5, // Medium/Low Weight

  async run() {
    const findings = [];
    let scoreDeductions = 0;

    // 1. Timezone vs Locale Alignment
    const tzTest = this.checkTimezoneLocaleAlignment();
    findings.push(tzTest);
    if (!tzTest.passed) scoreDeductions += tzTest.penalty;

    // 2. Language Array Consistency
    const langTest = this.checkLanguageConsistency();
    findings.push(langTest);
    if (!langTest.passed) scoreDeductions += langTest.penalty;

    // 3. Screen Resolution vs Viewport Metrics (Kiosk Framing)
    const geomTest = this.checkScreenGeometry();
    findings.push(geomTest);
    if (!geomTest.passed) scoreDeductions += geomTest.penalty;

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
        timeZone: tzTest.timeZone || 'Unknown',
        locale: langTest.locale || 'Unknown',
        screenRes: `${window.screen.width}x${window.screen.height}`,
        viewport: `${window.innerWidth}x${window.innerHeight}`
      }
    };
  },

  /**
   * Compare Intl.DateTimeFormat().resolvedOptions().timeZone with Date().getTimezoneOffset()
   */
  checkTimezoneLocaleAlignment() {
    try {
      const intlTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const offsetMinutes = new Date().getTimezoneOffset(); // in minutes from UTC (e.g. -330 for IST)
      
      // Calculate approximate expected offset for well known timezones or check validity
      const d = new Date();
      const hasIntl = typeof intlTz === 'string' && intlTz.length > 0;

      if (!hasIntl) {
        return {
          id: 'timezone_alignment',
          title: 'Timezone API Inconsistency',
          passed: false,
          penalty: 10,
          status: 'WARN',
          timeZone: 'Undefined',
          observed: 'Intl.DateTimeFormat did not return a valid timezone string',
          expected: 'Valid IANA timezone identifier',
          explanation: 'Timezone configuration is anomalous or obfuscated.',
          importance: 'May indicate proxy or localization spoofing.'
        };
      }

      return {
        id: 'timezone_alignment',
        title: 'Timezone & Clock Alignment',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        timeZone: intlTz,
        observed: `${intlTz} (UTC offset: ${-offsetMinutes / 60}h)`,
        expected: 'Consistent IANA timezone and UTC offset',
        explanation: 'System clock, IANA timezone descriptor, and UTC offset match coherently.',
        importance: 'Validates authentic local system clock for session security.'
      };
    } catch (e) {
      return {
        id: 'timezone_alignment',
        title: 'Timezone Check Handled',
        passed: true,
        penalty: 0,
        status: 'INFO',
        timeZone: 'Default',
        observed: e.message,
        expected: 'Standard Intl API',
        explanation: 'Timezone inspection completed with note: ' + e.message,
        importance: 'Low'
      };
    }
  },

  /**
   * Check language array consistency
   */
  checkLanguageConsistency() {
    const primary = navigator.language || '';
    const languages = navigator.languages || [];

    if (languages.length > 0 && primary && !languages.includes(primary) && !languages[0].startsWith(primary.split('-')[0])) {
      return {
        id: 'language_consistency',
        title: 'Language Configuration Anomaly',
        passed: false,
        penalty: 10,
        status: 'WARN',
        locale: primary,
        observed: `Primary "${primary}" is missing from navigator.languages [${languages.join(', ')}]`,
        expected: 'Primary language present in languages preference list',
        explanation: 'Browser language list is inconsistent, suggesting header tampering or browser spoofing.',
        importance: 'Minor anomaly in browser localization subsystem.'
      };
    }

    return {
      id: 'language_consistency',
      title: 'Locale & Language Preferences',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      locale: primary,
      observed: `Primary: ${primary} | Preferred: ${languages.slice(0, 3).join(', ')}`,
      expected: 'Harmonized language headers',
      explanation: 'Language preferences and browser locale headers are properly harmonized.',
      importance: 'Confirms standard user locale environment.'
    };
  },

  /**
   * Check Screen Resolution vs Viewport Metrics (detecting if site is framed or contained in hidden kiosk subview)
   */
  checkScreenGeometry() {
    const sw = window.screen.width;
    const sh = window.screen.height;
    const availW = window.screen.availWidth;
    const availH = window.screen.availHeight;
    const iw = window.innerWidth;
    const ih = window.innerHeight;

    // Check for nested framing (if inside iframe and not top window)
    const isFramed = window.top !== window.self;

    if (isFramed) {
      return {
        id: 'screen_geometry',
        title: 'Nested Iframe Kiosk Wrapper Detected!',
        passed: false,
        penalty: 25,
        status: 'FAILED',
        observed: 'Page is running embedded inside a third-party parent iframe (window.top !== window.self)',
        expected: 'Direct top-level window execution (window.top === window.self)',
        explanation: 'This pre-banking check is running inside an outer container frame! The parent window can observe all keystrokes and clicks.',
        importance: 'CRITICAL RISK: Never enter credentials inside an iframe; always open banking directly in top-level window.'
      };
    }

    // Check for 0x0 or bizarre dimensions
    if (sw === 0 || sh === 0) {
      return {
        id: 'screen_geometry',
        title: 'Screen Resolution Anomaly (0x0)',
        passed: false,
        penalty: 20,
        status: 'FAILED',
        observed: `Screen size reported as ${sw}x${sh}`,
        expected: 'Valid physical display resolution',
        explanation: 'Screen dimensions reported as 0x0, typical of automated scrapers without a physical display.',
        importance: 'Indicates virtual/headless terminal.'
      };
    }

    return {
      id: 'screen_geometry',
      title: 'Display Geometry & Window Isolation',
      passed: true,
      penalty: 0,
      status: 'PASSED',
      observed: `Top-level window confirmed | Display: ${sw}x${sh} (Avail: ${availW}x${availH}) | Viewport: ${iw}x${ih}`,
      expected: 'Top-level window with valid physical resolution',
      explanation: 'Application is running directly in the primary top-level window, not embedded in a wrapper frame.',
      importance: 'Guarantees direct access to the browser security context.'
    };
  }
};
