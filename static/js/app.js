/**
 * TRUST - terminal template adapter
 *
 * The page markup and visual styling live in index.html/terminal.css.
 * All security behavior comes from the detector, scoring, and simulator
 * modules shipped with TRUST. This file only connects those modules to the
 * template controls and renders their results into the existing UI.
 */

window.TRUST = window.TRUST || {};

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

window.TRUST.escapeHtml = escapeHtml;

const TEMPLATE_ATTACKS = {
  overlay: 'phishing_overlay',
  clipboard: 'clipboard_swapper',
  input: 'keylogger_hook',
  remote: 'webdriver_spoof'
};

const TERMINAL_COPY = {
  en: {
    safe: 'LOW RISK / browser checks passed',
    caution: 'MEDIUM RISK / verify before typing',
    danger: 'HIGH RISK / do not type credentials',
    safeCopy: 'No browser-visible integrity issue was detected. Complete the physical checklist before sensitive work.',
    cautionCopy: 'Some browser signals need attention. Verify the address and use a trusted device for sensitive work.',
    dangerCopy: 'A serious browser-visible risk was detected. Do not enter passwords on this terminal.',
    simClean: 'Your lab is clean. Activate a signal to see how the real TRUST detectors respond.',
    simActive: count => `${count} simulated attack${count === 1 ? '' : 's'} active — scan to measure the combined risk.`,
    scanReady: 'READY / no check has run',
    scanRunning: 'RUNNING / detector modules are probing the browser',
    scanDone: findings => `COMPLETE / ${findings} signal finding${findings === 1 ? '' : 's'} recorded`
  },
  hi: {
    safe: 'कम जोखिम / ब्राउज़र जाँच पास', caution: 'मध्यम जोखिम / टाइप करने से पहले जाँचें', danger: 'उच्च जोखिम / पासवर्ड न डालें',
    safeCopy: 'ब्राउज़र में कोई गंभीर समस्या नहीं मिली। संवेदनशील काम से पहले भौतिक जाँच पूरी करें.',
    cautionCopy: 'कुछ ब्राउज़र संकेतों पर ध्यान चाहिए। पता जाँचें और संवेदनशील काम के लिए भरोसेमंद डिवाइस इस्तेमाल करें.',
    dangerCopy: 'ब्राउज़र में गंभीर जोखिम मिला। इस टर्मिनल पर पासवर्ड न डालें.',
    simClean: 'लैब साफ है। TRUST डिटेक्टरों की प्रतिक्रिया देखने के लिए कोई संकेत सक्रिय करें.',
    simActive: count => `${count} सिम्युलेटेड अटैक सक्रिय — संयुक्त जोखिम मापने के लिए स्कैन चलाएँ.`,
    scanReady: 'तैयार / अभी कोई जाँच नहीं चली', scanRunning: 'जाँच जारी / ब्राउज़र डिटेक्टर चल रहे हैं',
    scanDone: findings => `पूर्ण / ${findings} संकेत रिकॉर्ड हुए`
  },
  mr: {
    safe: 'कमी धोका / ब्राउझर तपासणी पास', caution: 'मध्यम धोका / टाइप करण्यापूर्वी तपासा', danger: 'मोठा धोका / पासवर्ड टाकू नका',
    safeCopy: 'ब्राउझरमध्ये गंभीर समस्या आढळली नाही. संवेदनशील कामापूर्वी भौतिक तपासणी पूर्ण करा.',
    cautionCopy: 'काही ब्राउझर संकेतांकडे लक्ष द्या. संवेदनशील कामासाठी विश्वासू डिव्हाइस वापरा.',
    dangerCopy: 'ब्राउझरमध्ये गंभीर धोका आढळला. या टर्मिनलवर पासवर्ड टाकू नका.',
    simClean: 'लॅब स्वच्छ आहे. TRUST डिटेक्टरची प्रतिक्रिया पाहण्यासाठी संकेत सक्रिय करा.',
    simActive: count => `${count} सिम्युलेटेड हल्ले सक्रिय — एकत्रित धोका मोजण्यासाठी स्कॅन करा.`,
    scanReady: 'तयार / तपासणी झालेली नाही', scanRunning: 'तपासणी सुरू / ब्राउझर डिटेक्टर चालू आहेत',
    scanDone: findings => `पूर्ण / ${findings} संकेत नोंदवले`
  },
  es: {
    safe: 'RIESGO BAJO / navegador verificado', caution: 'RIESGO MEDIO / verifica antes de escribir', danger: 'RIESGO ALTO / no escribas credenciales',
    safeCopy: 'No se detectó una anomalía grave en el navegador. Completa la lista física antes de continuar.',
    cautionCopy: 'Algunas señales requieren atención. Verifica la dirección y usa un dispositivo confiable.',
    dangerCopy: 'Se detectó un riesgo grave en el navegador. No introduzcas contraseñas aquí.',
    simClean: 'El laboratorio está limpio. Activa una señal para ver la respuesta de TRUST.',
    simActive: count => `${count} ataque${count === 1 ? '' : 's'} simulado${count === 1 ? '' : 's'} activo${count === 1 ? '' : 's'} — analiza el riesgo combinado.`,
    scanReady: 'LISTO / no se ha ejecutado una comprobación', scanRunning: 'EJECUTANDO / los detectores están analizando el navegador',
    scanDone: findings => `COMPLETO / ${findings} señal${findings === 1 ? '' : 'es'} registrada${findings === 1 ? '' : 's'}`
  },
  fr: {
    safe: 'RISQUE FAIBLE / navigateur vérifié', caution: 'RISQUE MOYEN / vérifiez avant de saisir', danger: 'RISQUE ÉLEVÉ / ne saisissez pas de mot de passe',
    safeCopy: 'Aucun problème grave visible dans le navigateur. Terminez les vérifications physiques avant une action sensible.',
    cautionCopy: 'Certains signaux nécessitent votre attention. Vérifiez l’adresse et utilisez un appareil fiable.',
    dangerCopy: 'Un risque grave visible dans le navigateur a été détecté. Ne saisissez pas de mot de passe ici.',
    simClean: 'Votre laboratoire est propre. Activez un signal pour voir la réaction de TRUST.',
    simActive: count => `${count} attaque${count === 1 ? '' : 's'} simulée${count === 1 ? '' : 's'} active${count === 1 ? '' : 's'} — lancez une analyse.`,
    scanReady: 'PRÊT / aucune analyse exécutée', scanRunning: 'ANALYSE / les détecteurs sondent le navigateur',
    scanDone: findings => `TERMINÉ / ${findings} signal${findings === 1 ? '' : 'aux'} enregistré${findings === 1 ? '' : 's'}`
  }
};

window.TRUST.app = {
  currentEvaluation: null,
  isScanning: false,
  language: 'en',

  init() {
    if (window.TRUST.simulator) window.TRUST.simulator.init();
    window.TRUST.terminalI18n?.apply('en');
    this.setupToolNavigation();
    this.setupLanguageSelector();
    this.setupEventListeners();
    this.setupRevealAnimations();
    this.streamTerminal();
    this.updatePhysicalStatus();
    this.renderSimulation();
    window.setTimeout(() => document.getElementById('splash')?.classList.add('splash-hidden'), 2350);
    return this.runFullScan();
  },

  copy() {
    return window.TRUST.terminalI18n?.currentCopy?.() || TERMINAL_COPY[this.language] || TERMINAL_COPY.en;
  },

  setupToolNavigation() {
    document.querySelectorAll('.tool-tab').forEach(tab => tab.addEventListener('click', () => {
      const selected = tab.dataset.tool;
      document.querySelectorAll('.tool-tab').forEach(item => item.classList.toggle('active', item === tab));
      document.querySelectorAll('.tool-content').forEach(panel => panel.classList.toggle('active', panel.id === `tool-${selected}`));
      if (selected === 'simulator') this.renderSimulation();
    }));
  },

  setupLanguageSelector() {
    const select = document.getElementById('languageSelect');
    if (!select) return;
    select.addEventListener('change', event => {
      this.language = window.TRUST.terminalI18n?.translations[event.target.value] ? event.target.value : 'en';
      window.TRUST.terminalI18n?.apply(this.language);
      if (window.TRUST.i18n?.translations[this.language]) window.TRUST.i18n.currentLang = this.language;
      if (this.currentEvaluation) this.renderEvaluation(this.currentEvaluation);
      this.renderSimulation();
      this.streamTerminal();
    });
  },

  setupEventListeners() {
    document.getElementById('runScan')?.addEventListener('click', () => this.runFullScan());

    document.querySelectorAll('.switch').forEach(button => button.addEventListener('click', async () => {
      const attackId = TEMPLATE_ATTACKS[button.dataset.threat];
      if (!attackId || !window.TRUST.simulator) return;
      const isActive = window.TRUST.simulator.toggleAttack(attackId);
      button.classList.toggle('on', isActive);
      button.setAttribute('aria-pressed', String(isActive));
      this.renderSimulation();
      await this.runFullScan();
    }));

    document.getElementById('wipeSession')?.addEventListener('click', async () => {
      if (window.TRUST.reportExporter) window.TRUST.reportExporter.wipeSessionData();
      if (window.TRUST.simulator) window.TRUST.simulator.resetAll();
      document.querySelectorAll('.switch').forEach(button => {
        button.classList.remove('on');
        button.setAttribute('aria-pressed', 'false');
      });
      this.showToast(window.TRUST.terminalI18n?.get('wipeToast') || 'Demo state wiped. The terminal is back to a clean opening posture.');
      this.renderSimulation();
      await this.runFullScan();
    });

    document.querySelectorAll('[data-physical]').forEach(check => check.addEventListener('change', () => this.updatePhysicalStatus()));
    document.getElementById('enterToolkit')?.addEventListener('click', () => window.setTimeout(() => document.getElementById('runScan')?.focus(), 450));

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && window.TRUST.simulator?.activeAttacks?.size) {
        window.TRUST.simulator.resetAll();
        document.querySelectorAll('.switch').forEach(button => button.classList.remove('on'));
        this.showToast(window.TRUST.terminalI18n?.get('disarmToast') || 'All simulated attacks disarmed.');
        this.runFullScan();
      }
    });
  },

  setupRevealAnimations() {
    const targets = document.querySelectorAll('[data-reveal]');
    if (!('IntersectionObserver' in window)) { targets.forEach(target => target.classList.add('in')); return; }
    const observer = new IntersectionObserver(entries => entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('in'); observer.unobserve(entry.target); }
    }), { threshold: 0.12 });
    targets.forEach(target => observer.observe(target));
  },

  async runFullScan() {
    if (this.isScanning) return;
    this.isScanning = true;
    const button = document.getElementById('runScan');
    const progress = document.getElementById('scanProgress');
    const status = document.getElementById('scanStatus');
    if (button) { button.disabled = true; button.textContent = window.TRUST.i18n?.get('btnRunning') || 'Analyzing signals...'; }
    if (progress) progress.style.width = '12%';
    if (status) status.textContent = this.copy().scanRunning;

    try {
      const results = await Promise.all([
        window.TRUST.detectors.inputTiming.run(),
        window.TRUST.detectors.domScript.run(),
        window.TRUST.detectors.clipboard.run(),
        window.TRUST.detectors.browserEnv.run(),
        window.TRUST.detectors.canvasWebgl.run(),
        window.TRUST.detectors.networkSignals.run(),
        window.TRUST.detectors.environment.run()
      ]);
      this.currentEvaluation = window.TRUST.scoring.evaluate({
        inputTiming: results[0], domScript: results[1], clipboard: results[2], browserEnv: results[3],
        canvasWebgl: results[4], networkSignals: results[5], environment: results[6]
      });
      if (progress) progress.style.width = '100%';
      this.renderEvaluation(this.currentEvaluation);
      this.showToast(window.TRUST.terminalI18n?.get('scanToast', { score: this.currentEvaluation.score, verdict: this.verdictFor(this.currentEvaluation).title }) || `Scan complete: ${this.currentEvaluation.score}/100 — ${this.verdictFor(this.currentEvaluation).title}`);
    } catch (error) {
      console.error('TRUST scan failed:', error);
      if (status) status.textContent = window.TRUST.terminalI18n?.get('scanErrorStatus') || 'ERROR / detector scan could not complete';
      this.showToast(window.TRUST.terminalI18n?.get('scanErrorToast') || 'The scan could not complete. Refresh the page and try again.');
    } finally {
      this.isScanning = false;
      if (button) { button.disabled = false; button.textContent = window.TRUST.i18n?.get('btnRunScan') || 'Run safety check →'; }
    }
  },

  verdictFor(evaluation) {
    if (evaluation.trafficLight === 'red') return { title: this.copy().danger, copy: this.copy().dangerCopy, color: 'var(--red)' };
    if (evaluation.trafficLight === 'yellow') return { title: this.copy().caution, copy: this.copy().cautionCopy, color: 'var(--orange)' };
    return { title: this.copy().safe, copy: this.copy().safeCopy, color: 'var(--cyan)' };
  },

  renderEvaluation(evaluation) {
    const verdict = this.verdictFor(evaluation);
    const score = Math.max(0, Math.min(100, evaluation.score));
    this.animateNumber(document.getElementById('scoreValue'), score);
    const verdictTitle = document.getElementById('verdict');
    const verdictCopy = document.getElementById('verdictCopy');
    const scanStatus = document.getElementById('scanStatus');
    if (verdictTitle) verdictTitle.textContent = verdict.title;
    if (verdictCopy) verdictCopy.textContent = verdict.copy;
    if (scanStatus) scanStatus.textContent = this.copy().scanDone(evaluation.findings.length);
    this.setRing(document.getElementById('scoreRing'), score, verdict.color);
    this.renderSignalList(evaluation);
    this.renderSimulation(evaluation);
  },

  renderSignalList(evaluation) {
    const list = document.getElementById('signalList');
    if (!list) return;
    list.innerHTML = Object.values(evaluation.categoryBreakdown || {}).map(category => {
      const categoryStatus = category.status || 'INFO';
      const statusClass = categoryStatus === 'PASSED' ? 'pass' : categoryStatus === 'WARN' ? 'caution' : 'risk';
      const findings = category.findingsCount || 0;
      const statusLabel = window.TRUST.terminalI18n?.get(`status${categoryStatus}`) || categoryStatus;
      const findingLabel = window.TRUST.terminalI18n?.get(findings === 1 ? 'findingOne' : 'findingMany') || `finding${findings === 1 ? '' : 's'}`;
      return `<div class="signal"><span>${escapeHtml(category.name || 'Detector')}</span><b class="${statusClass}">${escapeHtml(statusLabel)} / ${escapeHtml(category.score)}</b><b class="${statusClass}">${findings} ${escapeHtml(findingLabel)}</b></div>`;
    }).join('');
  },

  renderSimulation(evaluation = this.currentEvaluation) {
    const active = window.TRUST.simulator?.activeAttacks?.size || 0;
    const score = evaluation ? evaluation.score : 100;
    const verdict = evaluation ? this.verdictFor(evaluation) : { color: 'var(--cyan)' };
    this.animateNumber(document.getElementById('simScore'), score);
    const simVerdict = document.getElementById('simVerdict');
    const simCopy = document.getElementById('simCopy');
    if (simVerdict) simVerdict.textContent = active ? this.copy().simActive(active) : (window.TRUST.terminalI18n?.get('simNone') || 'No simulated threats');
    if (simCopy) simCopy.textContent = active ? this.copy().simActive(active) : this.copy().simClean;
    this.setRing(document.getElementById('simRing'), score, verdict.color);
  },

  setRing(ring, score, color) {
    if (!ring) return;
    ring.style.setProperty('--score', score);
    ring.style.background = `conic-gradient(${color} 0deg, ${color} ${score * 3.6}deg, rgba(255,255,255,.08) ${score * 3.6}deg)`;
  },

  animateNumber(element, target) {
    if (!element) return;
    const start = Number(element.textContent) || 0;
    const startTime = performance.now();
    const frame = now => {
      const progress = Math.min(1, (now - startTime) / 450);
      element.textContent = String(Math.round(start + ((target - start) * progress)));
      if (progress < 1) window.requestAnimationFrame(frame);
    };
    window.requestAnimationFrame(frame);
  },

  updatePhysicalStatus() {
    const checks = Array.from(document.querySelectorAll('[data-physical]'));
    const done = checks.filter(check => check.checked).length;
    const status = document.getElementById('physicalStatus');
    if (status) {
      status.textContent = window.TRUST.terminalI18n?.get('physicalStatus', { done, total: checks.length }) || `${done} of ${checks.length} checks complete`;
      status.classList.toggle('ready', done === checks.length);
    }
  },

  streamTerminal() {
    const terminal = document.getElementById('terminalBody');
    if (!terminal) return;
    window.clearTimeout(this.terminalTimer);
    terminal.innerHTML = '';
    const labels = window.TRUST.terminalI18n?.get('terminalLines');
    const lines = Array.isArray(labels) ? labels : [
      ['inspect browser-visible input hooks', 'ok', 'native listener surface'],
      ['probe overlay geometry --viewport', 'ok', 'no suspicious layers'],
      ['write clipboard canary --roundtrip', 'ok', 'token integrity checked'],
      ['check navigator.webdriver', 'warn', 'informational signal'],
      ['raster canvas --multi-pass', 'ok', 'rendering consistency checked'],
      ['measure network context', 'warn', 'informational signal'],
      ['score --explainable --attack-load', 'ok', 'cumulative risk model ready']
    ];
    const okLabel = window.TRUST.terminalI18n?.get('terminalOk') || 'OK';
    const warnLabel = window.TRUST.terminalI18n?.get('terminalWarn') || 'WARN';
    let index = 0;
    const write = () => {
      const line = lines[index % lines.length];
      const type = line[2] ? line[1] : ([3, 5].includes(index % 7) ? 'warn' : 'ok');
      const detail = line[2] || line[1];
      const row = document.createElement('div');
      row.className = 'cmd-line';
      row.innerHTML = `<span class="prompt">trust@surface$ </span>${escapeHtml(line[0])}<span class="${type === 'warn' ? 'warn' : 'ok'}"> [${type === 'warn' ? warnLabel : okLabel}] </span><span class="dim">${escapeHtml(detail)}</span>`;
      terminal.appendChild(row);
      while (terminal.children.length > 10) terminal.firstElementChild.remove();
      index += 1;
      this.terminalTimer = window.setTimeout(write, 720);
    };
    write();
  },

  showToast(message) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => toast.classList.remove('show'), 3200);
  }
};

window.addEventListener('DOMContentLoaded', () => window.TRUST.app.init());
