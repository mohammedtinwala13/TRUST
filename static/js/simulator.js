/**
 * TRUST - Threat & Attack Simulator
 * Allows security evaluators and users to test how TRUST reacts in real-time
 * to active attacks (Keyloggers, Overlays, Clipboard Swappers, Webdriver, etc.)
 */

window.TRUST = window.TRUST || {};

window.TRUST.simulator = {
  activeAttacks: new Set(),
  _originalMethods: {},
  _injectedElements: [],

  init() {
    // Save original pristine references
    this._originalMethods.addEventListener = EventTarget.prototype.addEventListener;
    this._originalMethods.removeEventListener = EventTarget.prototype.removeEventListener;
    this._originalMethods.fetch = window.fetch;
    this._originalMethods.toDataURL = HTMLCanvasElement.prototype.toDataURL;
    this._originalMethods.toString = Function.prototype.toString;
  },

  /**
   * Toggle attack state
   */
  toggleAttack(attackId) {
    if (this.activeAttacks.has(attackId)) {
      this.disarmAttack(attackId);
      return false;
    } else {
      this.armAttack(attackId);
      return true;
    }
  },

  /**
   * Arm a specific attack simulation
   */
  armAttack(attackId) {
    this.activeAttacks.add(attackId);

    switch (attackId) {
      case 'keylogger_hook':
        this._armKeyloggerHook();
        break;
      case 'prototype_tamper':
        this._armPrototypeTamper();
        break;
      case 'phishing_overlay':
        this._armPhishingOverlay();
        break;
      case 'clipboard_swapper':
        this._armClipboardSwapper();
        break;
      case 'webdriver_spoof':
        this._armWebdriverSpoof();
        break;
      case 'bot_keystrokes':
        this._armBotKeystrokes();
        break;
      case 'canvas_noise':
        this._armCanvasNoise();
        break;
      default:
        console.warn('Unknown attack simulation ID:', attackId);
    }
  },

  /**
   * Disarm an attack simulation
   */
  disarmAttack(attackId) {
    this.activeAttacks.delete(attackId);

    switch (attackId) {
      case 'keylogger_hook':
        this._disarmKeyloggerHook();
        break;
      case 'prototype_tamper':
        this._disarmPrototypeTamper();
        break;
      case 'phishing_overlay':
        this._disarmPhishingOverlay();
        break;
      case 'clipboard_swapper':
        this._disarmClipboardSwapper();
        break;
      case 'webdriver_spoof':
        this._disarmWebdriverSpoof();
        break;
      case 'bot_keystrokes':
        this._disarmBotKeystrokes();
        break;
      case 'canvas_noise':
        this._disarmCanvasNoise();
        break;
    }
  },

  /**
   * Reset all simulations to clean baseline
   */
  resetAll() {
    const attacks = Array.from(this.activeAttacks);
    attacks.forEach(att => this.disarmAttack(att));
    this.activeAttacks.clear();
    window.TRUST._simulatedWebdriver = false;
    window.TRUST._simulatedCanvasNoise = false;
    window.TRUST._canaryTestResult = null;
    window.TRUST._keystrokeSamples = [];
  },

  // --- ATTACK IMPLEMENTATIONS ---

  _armKeyloggerHook() {
    const origAdd = this._originalMethods.addEventListener;
    // Overwrite addEventListener with custom wrapper (classic kiosk keylogger hook)
    EventTarget.prototype.addEventListener = function(type, listener, options) {
      if (type === 'keydown' || type === 'keypress' || type === 'keyup') {
        // Interceptor hook
        const loggedListener = function(evt) {
          // Simulated keylogger exfiltration hook
          return listener.apply(this, arguments);
        };
        return origAdd.call(this, type, loggedListener, options);
      }
      return origAdd.apply(this, arguments);
    };
    window.TRUST.keyloggerActive = true;
  },

  _disarmKeyloggerHook() {
    EventTarget.prototype.addEventListener = this._originalMethods.addEventListener;
    delete window.TRUST.keyloggerActive;
    delete window.keyloggerActive;
  },

  _armPrototypeTamper() {
    // Monkey-patch window.fetch
    const origFetch = this._originalMethods.fetch;
    window.fetch = function(input, init) {
      // Malicious wrapper stealing tokens
      return origFetch.apply(this, arguments);
    };

    // Monkey-patch canvas toDataURL
    const origToDataURL = this._originalMethods.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
      return origToDataURL.apply(this, arguments);
    };

    window._selenium_evaluate = true;
    window.malwareHook = 'active';
  },

  _disarmPrototypeTamper() {
    window.fetch = this._originalMethods.fetch;
    HTMLCanvasElement.prototype.toDataURL = this._originalMethods.toDataURL;
    delete window._selenium_evaluate;
    delete window.malwareHook;
  },

  _armPhishingOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'simulated-malicious-overlay';
    overlay.className = 'simulated-attacker-element';
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100vw';
    overlay.style.height = '100vh';
    overlay.style.zIndex = '99999';
    overlay.style.opacity = '0.02';
    overlay.style.backgroundColor = '#000000';
    overlay.style.pointerEvents = 'auto';  // Fixed: Changed from 'none' to 'auto' so overlay detector can catch it
    overlay.title = 'Simulated Deceptive Phishing Mask';
    document.body.appendChild(overlay);
    this._injectedElements.push(overlay);
  },

  _disarmPhishingOverlay() {
    const overlay = document.getElementById('simulated-malicious-overlay');
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }
  },

  _armClipboardSwapper() {
    // Set up a canary hijack simulation
    window.TRUST._canaryTestResult = {
      written: 'TRUST-CANARY-984218-IFSC-SBIN0001824',
      read: 'ATTACKER-WALLET-0x71C6634C253244EF3070E20D207337A56571A355',
      success: true,
      hijacked: true,
      error: null,
      timestamp: Date.now()
    };
  },

  _disarmClipboardSwapper() {
    window.TRUST._canaryTestResult = null;
  },

  _armWebdriverSpoof() {
    window.TRUST._simulatedWebdriver = true;
    window.__nightmare = true;
    window.cdc_adoQpoasnfa76pfcZLmcfl_Array = true;
  },

  _disarmWebdriverSpoof() {
    window.TRUST._simulatedWebdriver = false;
    delete window.__nightmare;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
  },

  _armBotKeystrokes() {
    // Generate robotic keystroke samples with zero jitter and <2ms dwell time
    window.TRUST._keystrokeSamples = [
      { key: 'A', dwellTime: 1.2, flightTime: 0.8 },
      { key: 'd', dwellTime: 1.1, flightTime: 0.9 },
      { key: 'm', dwellTime: 1.2, flightTime: 0.8 },
      { key: 'i', dwellTime: 1.1, flightTime: 0.9 },
      { key: 'n', dwellTime: 1.2, flightTime: 0.8 },
      { key: '1', dwellTime: 1.1, flightTime: 0.9 },
      { key: '2', dwellTime: 1.2, flightTime: 0.8 },
      { key: '3', dwellTime: 1.1, flightTime: 0.9 }
    ];
  },

  _disarmBotKeystrokes() {
    window.TRUST._keystrokeSamples = [];
  },

  _armCanvasNoise() {
    window.TRUST._simulatedCanvasNoise = true;
  },

  _disarmCanvasNoise() {
    window.TRUST._simulatedCanvasNoise = false;
  }
};
