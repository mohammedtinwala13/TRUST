/**
 * TRUST - Scoring & Explainability Engine
 * Computes weighted composite Trust Score (0-100), risk tier,
 * confidence level, and generates explainable security advice.
 */

window.TRUST = window.TRUST || {};

window.TRUST.scoring = {
  /**
   * Relative weights for each detector module. The evaluator normalizes by
   * the total so the score remains on a 0-100 scale.
   */
  WEIGHTS: {
    inputTiming: 25,
    domScript: 25,
    clipboard: 20,
    browserEnv: 15,
    canvasWebgl: 10,
    environment: 5,  // Fixed: Changed from 3 to 5
    networkSignals: 5  // Fixed: Changed from 2 to 5
  },

  /**
   * Calculate composite trust score and explainable report
   * @param {Object} detectorResults - Key-value map of results from all detectors
   */
  evaluate(detectorResults) {
    let totalWeight = 0;
    let weightedScoreSum = 0;
    const allFindings = [];
    const categoryBreakdown = {};
    let criticalFailures = 0;
    let highWarnings = 0;

    for (const [key, result] of Object.entries(detectorResults)) {
      const weight = this.WEIGHTS[key] || result.weight || 10;
      const score = Math.max(0, Math.min(100, result.score || 0));
      
      totalWeight += weight;
      weightedScoreSum += (score * weight);

      categoryBreakdown[key] = {
        id: result.id,
        name: result.name,
        category: result.category,
        weight,
        score,
        status: result.status,
        findingsCount: result.findings ? result.findings.length : 0,
        telemetry: result.telemetry || {}
      };

      if (result.findings && Array.isArray(result.findings)) {
        result.findings.forEach(f => {
          allFindings.push({
            ...f,
            detectorId: key,
            detectorName: result.name
          });

          if (f.status === 'FAILED' && (f.penalty || 0) >= 25) {
            criticalFailures++;
          } else if (f.status === 'FAILED' || f.status === 'WARN') {
            highWarnings++;
          }
        });
      }
    }

    // Baseline normalized score (0 - 100)
    let compositeScore = totalWeight > 0 ? Math.round(weightedScoreSum / totalWeight) : 0;

    // Hard cap score if critical security failure detected (e.g. keylogger hook or monkey-patched prototype)
    if (criticalFailures > 0 && compositeScore > 55) {
      compositeScore = Math.min(55, compositeScore);
    }

    // Active simulations represent concurrent attack paths. Keep the
    // detector-derived score as the baseline, then apply a progressive load
    // penalty so additional active attacks always make the terminal riskier.
    // The triangular curve makes the second and later attack paths count more
    // heavily than the first, while the final score remains clamped to 0.
    const activeAttackCount = window.TRUST.simulator?.activeAttacks?.size || 0;
    const attackLoadPenalty = activeAttackCount > 0
      ? Math.min(100, activeAttackCount * (activeAttackCount + 1) * 2)
      : 0;
    compositeScore = Math.max(0, compositeScore - attackLoadPenalty);

    // Determine Risk Level & Color
    let riskLevel = 'LOW';
    let riskColor = '#10b981'; // Green
    let trafficLight = 'green';
    let recommendation = '';
    let recommendationTitle = '';

    if (compositeScore >= 90) {
      riskLevel = 'LOW';
      riskColor = '#10b981';
      trafficLight = 'green';
      recommendationTitle = 'Safe to Proceed with Banking Entry';
      recommendation = 'All primary browser sandbox and input pipelines are clean. No anomalous hooks, clipboard swappers, or deceptive overlays detected. You may proceed with caution.';
    } else if (compositeScore >= 70) {
      riskLevel = 'MEDIUM';
      riskColor = '#f59e0b'; // Amber / Yellow
      trafficLight = 'yellow';
      recommendationTitle = 'Proceed with Heightened Caution';
      recommendation = 'Minor variances or configuration anomalies were detected (e.g., elevated latency, missing permissions, or rendering quirks). Verify the exact banking URL, use the bank\'s virtual keyboard, and never save passwords.';
    } else {
      riskLevel = 'HIGH';
      riskColor = '#ef4444'; // Red
      trafficLight = 'red';
      recommendationTitle = 'CRITICAL DANGER — DO NOT ENTER PASSWORDS';
      recommendation = 'Critical security risks detected! Active event listener hooks, prototype tampering, synthetic event injection, or deceptive fullscreen overlays were found on this terminal. Do NOT type bank credentials or passwords here.';
    }

    // Compute Confidence Level (HIGH / MEDIUM / LOW)
    let confidence = 'HIGH';
    let confidenceReason = 'Comprehensive multi-signal validation across all 7 detector subsystems.';
    const keystrokeSamples = window.TRUST._keystrokeSamples ? window.TRUST._keystrokeSamples.length : 0;
    
    if (keystrokeSamples < 5) {
      confidence = 'MEDIUM';
      confidenceReason = 'Static and prototype checks completed with high confidence; interactive typing cadence has not yet been exercised.';
    }

    // Categorized Signal Summaries for Quick Bullets
    const passedSignals = allFindings.filter(f => f.status === 'PASSED');
    const warningSignals = allFindings.filter(f => f.status === 'WARN');
    const failedSignals = allFindings.filter(f => f.status === 'FAILED');

    return {
      score: compositeScore,
      riskLevel,
      riskColor,
      trafficLight,
      confidence,
      confidenceReason,
      recommendationTitle,
      recommendation,
      timestamp: new Date().toISOString(),
      summaryBullets: this.generateSummaryBullets(allFindings, compositeScore),
      findings: allFindings,
      passedSignals,
      warningSignals,
      failedSignals,
      categoryBreakdown,
      criticalFailures,
      highWarnings,
      activeAttackCount,
      attackLoadPenalty
    };
  },

  /**
   * Generate human-readable explainable bullets
   */
  generateSummaryBullets(findings, score) {
    const bullets = [];

    // Prioritize failures first
    const failures = findings.filter(f => f.status === 'FAILED');
    failures.forEach(f => {
      bullets.push({
        type: 'danger',
        icon: '🚨',
        tag: 'CRITICAL',
        title: f.title,
        text: f.observed,
        importance: f.importance
      });
    });

    // Then warnings
    const warnings = findings.filter(f => f.status === 'WARN');
    warnings.forEach(w => {
      bullets.push({
        type: 'warning',
        icon: '⚠️',
        tag: 'WARNING',
        title: w.title,
        text: w.observed,
        importance: w.importance
      });
    });

    // Then top positive passes
    const passes = findings.filter(f => f.status === 'PASSED');
    passes.slice(0, 4).forEach(p => {
      bullets.push({
        type: 'success',
        icon: '✓',
        tag: 'SECURE',
        title: p.title,
        text: p.observed,
        importance: p.importance
      });
    });

    return bullets;
  }
};
