/**
 * TRUST - Report Exporter & Audit Logging Tool
 * Generates downloadable JSON audit logs, printable PDF certificates,
 * and performs secure session wiping.
 */

window.TRUST = window.TRUST || {};

window.TRUST.reportExporter = {
  /**
   * Export audit log as downloadable JSON
   */
  exportJSON(evaluation) {
    if (!evaluation) return;

    const data = {
      product: 'TRUST (Terminal Risk & Unseen Signal Tracker)',
      version: '1.0.0',
      terminalAuditTimestamp: evaluation.timestamp || new Date().toISOString(),
      trustScore: evaluation.score,
      riskLevel: evaluation.riskLevel,
      confidence: evaluation.confidence,
      recommendation: evaluation.recommendation,
      terminalFingerprint: this.generateTerminalFingerprint(),
      environment: {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        screen: `${window.screen.width}x${window.screen.height}`,
        isSecureContext: window.isSecureContext
      },
      categoryBreakdown: evaluation.categoryBreakdown,
      signals: evaluation.findings
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trust-security-audit-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  /**
   * Trigger clean printable view for PDF generation
   */
  printReport() {
    window.print();
  },

  /**
   * Wipe all session storage, local storage, test keys, and history state
   */
  wipeSessionData() {
    try {
      localStorage.clear();
      sessionStorage.clear();
      
      // Clear cookies
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i];
        const eqPos = cookie.indexOf('=');
        const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
        document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/';
      }

      window.TRUST._keystrokeSamples = [];
      window.TRUST._canaryTestResult = null;

      return true;
    } catch (e) {
      console.error('Session wiping error:', e);
      return false;
    }
  },

  /**
   * Deterministic terminal hash generator
   */
  generateTerminalFingerprint() {
    const raw = `${navigator.userAgent}|${navigator.platform}|${window.screen.width}x${window.screen.height}|${navigator.language}`;
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
      hash = ((hash << 5) - hash) + raw.charCodeAt(i);
      hash |= 0;
    }
    return 'TERM-' + Math.abs(hash).toString(16).toUpperCase().padStart(8, '0');
  }
};
