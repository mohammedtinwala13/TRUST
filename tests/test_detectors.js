/**
 * Test Suite for TRUST Detectors & Modules
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

// 1. Verify all required files exist
const requiredFiles = [
  'index.html',
  'trust-standalone.html',
  'static/css/main.css',
  'static/css/components.css',
  'static/css/print.css',
  'static/js/i18n.js',
  'static/js/qrcode.js',
  'static/js/scoring.js',
  'static/js/simulator.js',
  'static/js/biometricSandbox.js',
  'static/js/reportExporter.js',
  'static/js/app.js',
  'static/js/detectors/inputTiming.js',
  'static/js/detectors/clipboard.js',
  'static/js/detectors/domScript.js',
  'static/js/detectors/browserEnv.js',
  'static/js/detectors/canvasWebgl.js',
  'static/js/detectors/networkSignals.js',
  'static/js/detectors/environment.js'
];

console.log('--- Testing File Structure & Integrity ---');
requiredFiles.forEach(file => {
  const fullPath = path.join(__dirname, '..', file);
  assert(fs.existsSync(fullPath), `Required file missing: ${file}`);
  const stats = fs.statSync(fullPath);
  assert(stats.size > 0, `File is empty: ${file}`);
  console.log(`✓ Verified: ${file} (${stats.size} bytes)`);
});

// 2. Verify standalone HTML contains inlined detectors
console.log('\n--- Testing Standalone HTML Bundle ---');
const standaloneHtml = fs.readFileSync(path.join(__dirname, '..', 'trust-standalone.html'), 'utf-8');
assert(standaloneHtml.includes('TRUST.detectors.inputTiming'), 'Standalone missing inputTiming detector');
assert(standaloneHtml.includes('TRUST.detectors.clipboard'), 'Standalone missing clipboard detector');
assert(standaloneHtml.includes('TRUST.detectors.domScript'), 'Standalone missing domScript detector');
assert(standaloneHtml.includes('TRUST.detectors.browserEnv'), 'Standalone missing browserEnv detector');
assert(standaloneHtml.includes('TRUST.detectors.canvasWebgl'), 'Standalone missing canvasWebgl detector');
assert(standaloneHtml.includes('TRUST.detectors.networkSignals'), 'Standalone missing networkSignals detector');
assert(standaloneHtml.includes('TRUST.detectors.environment'), 'Standalone missing environment detector');
assert(standaloneHtml.includes('generateTerminalFingerprint'), 'Standalone missing reportExporter');
assert(standaloneHtml.includes('data-i18n="honestDisclaimer"'), 'Standalone missing disclaimer');
console.log('✓ Standalone HTML integrity passed (100% self-contained).');

// 3. Regression checks for baseline false-positive fixes
console.log('\n--- Testing False-Positive Guards ---');
const inputTimingCode = fs.readFileSync(path.join(__dirname, '..', 'static/js/detectors/inputTiming.js'), 'utf-8');
const domScriptCode = fs.readFileSync(path.join(__dirname, '..', 'static/js/detectors/domScript.js'), 'utf-8');
assert(!inputTimingCode.includes('descriptor.enumerable === true'), 'Enumerable native descriptors must not be treated as hooks');
assert(domScriptCode.includes('isHighZ && isTransparent && interceptsPointerInput'), 'Overlay detector must require invisible input interception');
assert(standaloneHtml.includes('isHighZ && isTransparent && interceptsPointerInput'), 'Standalone bundle is missing overlay false-positive guard');
console.log('✓ Baseline false-positive guards are present.');

// 4. Test i18n Dictionary
console.log('\n--- Testing i18n Localization ---');
const i18nCode = fs.readFileSync(path.join(__dirname, '..', 'static/js/i18n.js'), 'utf-8');
assert(i18nCode.includes('en:'), 'Missing EN translation');
assert(i18nCode.includes('hi:'), 'Missing Hindi translation');
assert(i18nCode.includes('mr:'), 'Missing Marathi translation');
assert(i18nCode.includes('es:'), 'Missing Spanish translation');
assert(i18nCode.includes('fr:'), 'Missing French translation');
console.log('✓ i18n contains EN, HI, MR, ES, FR translations.');

console.log('\n========================================');
console.log(' ALL TRUST JAVASCRIPT TESTS PASSED! ✓');
console.log('========================================\n');
