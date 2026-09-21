/**
 * TRUST - Interactive Biometric Keystroke Dynamics Sandbox
 * Records live typing cadences, plots dwell/flight distributions,
 * and benchmarks human physical variance against robotic key injection.
 */

window.TRUST = window.TRUST || {};

window.TRUST.biometricSandbox = {
  activeKeydowns: new Map(),
  lastKeyUpTime: null,
  samples: [],
  maxSamples: 30,

  init(inputElement, canvasElement, statsElement) {
    if (!inputElement) return;

    this.inputElement = inputElement;
    this.canvasElement = canvasElement;
    this.statsElement = statsElement;
    this.samples = [];
    window.TRUST._keystrokeSamples = this.samples;

    inputElement.addEventListener('keydown', (e) => this.handleKeyDown(e));
    inputElement.addEventListener('keyup', (e) => this.handleKeyUp(e));
  },

  handleKeyDown(e) {
    const now = performance.now();
    const key = e.key;

    if (!this.activeKeydowns.has(key)) {
      let flightTime = 0;
      if (this.lastKeyUpTime !== null) {
        flightTime = now - this.lastKeyUpTime;
      }
      this.activeKeydowns.set(key, { pressTime: now, flightTime });
    }
  },

  handleKeyUp(e) {
    const now = performance.now();
    const key = e.key;

    if (this.activeKeydowns.has(key)) {
      const data = this.activeKeydowns.get(key);
      const dwellTime = now - data.pressTime;
      this.lastKeyUpTime = now;
      this.activeKeydowns.delete(key);

      // Record sample
      const sample = {
        key: key.length === 1 ? key : 'Special',
        dwellTime: Math.round(dwellTime * 10) / 10,
        flightTime: Math.round(data.flightTime * 10) / 10,
        timestamp: now,
        isTrusted: e.isTrusted
      };

      this.samples.push(sample);
      if (this.samples.length > this.maxSamples) {
        this.samples.shift();
      }

      window.TRUST._keystrokeSamples = this.samples;

      this.updateStats();
      this.drawChart();
    }
  },

  updateStats() {
    if (!this.statsElement) return;

    if (this.samples.length === 0) {
      this.statsElement.innerHTML = `
        <div class="biometric-stat-item"><span>Samples:</span> <strong>0</strong></div>
        <div class="biometric-stat-item"><span>Avg Dwell:</span> <strong>-- ms</strong></div>
        <div class="biometric-stat-item"><span>Avg Flight:</span> <strong>-- ms</strong></div>
        <div class="biometric-stat-item"><span>Jitter (StdDev):</span> <strong>-- ms</strong></div>
        <div class="biometric-stat-item"><span>Classification:</span> <span class="badge badge-neutral">Awaiting Input</span></div>
      `;
      return;
    }

    const dwells = this.samples.map(s => s.dwellTime);
    const flights = this.samples.map(s => s.flightTime).filter(f => f > 0);

    const avgDwell = dwells.reduce((a, b) => a + b, 0) / dwells.length;
    const avgFlight = flights.length ? flights.reduce((a, b) => a + b, 0) / flights.length : 0;
    
    const variance = dwells.length > 1
      ? dwells.reduce((sum, d) => sum + Math.pow(d - avgDwell, 2), 0) / (dwells.length - 1)
      : 0;
    const stdDev = Math.sqrt(variance);

    const isHuman = stdDev >= 12 && avgDwell >= 30;
    const badgeClass = isHuman ? 'badge-success' : this.samples.length < 5 ? 'badge-neutral' : 'badge-danger';
    const badgeText = isHuman ? 'Human Biometric Profile' : this.samples.length < 5 ? 'Gathering Data...' : 'Bot / Scripted Injection';

    this.statsElement.innerHTML = `
      <div class="biometric-stat-item"><span>Recorded Samples:</span> <strong>${this.samples.length}</strong></div>
      <div class="biometric-stat-item"><span>Avg Dwell (Hold):</span> <strong>${avgDwell.toFixed(1)} ms</strong></div>
      <div class="biometric-stat-item"><span>Avg Flight (Interval):</span> <strong>${avgFlight.toFixed(1)} ms</strong></div>
      <div class="biometric-stat-item"><span>Jitter (Variance):</span> <strong>±${stdDev.toFixed(1)} ms</strong></div>
      <div class="biometric-stat-item"><span>Classification:</span> <span class="badge ${badgeClass}">${badgeText}</span></div>
    `;
  },

  drawChart() {
    if (!this.canvasElement) return;
    const canvas = this.canvasElement;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    // Background grid
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let y = 20; y < height; y += 30) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    if (this.samples.length === 0) {
      ctx.fillStyle = '#64748b';
      ctx.font = '12px system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Type sample text above to plot live keystroke cadence graph', width / 2, height / 2);
      return;
    }

    const barWidth = Math.max(6, Math.floor((width - 40) / this.samples.length) - 4);
    const maxVal = Math.max(250, ...this.samples.map(s => Math.max(s.dwellTime, s.flightTime)));

    this.samples.forEach((sample, i) => {
      const x = 20 + i * (barWidth + 4);

      // Dwell bar (Hold time - Cyan)
      const dwellHeight = (sample.dwellTime / maxVal) * (height - 40);
      const yDwell = height - 20 - dwellHeight;
      ctx.fillStyle = '#06b6d4'; // Cyan
      ctx.fillRect(x, yDwell, barWidth / 2, dwellHeight);

      // Flight bar (Interval - Violet)
      const flightHeight = (sample.flightTime / maxVal) * (height - 40);
      const yFlight = height - 20 - flightHeight;
      ctx.fillStyle = '#8b5cf6'; // Violet
      ctx.fillRect(x + barWidth / 2, yFlight, barWidth / 2, flightHeight);

      // Key label
      ctx.fillStyle = '#94a3b8';
      ctx.font = '9px monospace';
      ctx.textAlign = 'center';
      ctx.fillText(sample.key.slice(0, 2), x + barWidth / 2, height - 6);
    });

    // Legend in corner
    ctx.fillStyle = '#06b6d4';
    ctx.fillRect(width - 140, 10, 10, 8);
    ctx.fillStyle = '#cbd5e1';
    ctx.font = '10px system-ui, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText('Dwell Time', width - 125, 17);

    ctx.fillStyle = '#8b5cf6';
    ctx.fillRect(width - 70, 10, 10, 8);
    ctx.fillStyle = '#cbd5e1';
    ctx.fillText('Flight Time', width - 55, 17);
  },

  reset() {
    this.samples = [];
    window.TRUST._keystrokeSamples = [];
    this.activeKeydowns.clear();
    this.lastKeyUpTime = null;
    if (this.inputElement) this.inputElement.value = '';
    this.updateStats();
    this.drawChart();
  }
};
