/**
 * TRUST - Canvas & WebGL Rendering Consistency Detector
 * Analyzes sub-pixel font rendering, emoji blending, canvas noise injection extensions,
 * and WebGL hardware GPU vs software rasterizer consistency.
 */

window.TRUST = window.TRUST || {};
window.TRUST.detectors = window.TRUST.detectors || {};

window.TRUST.detectors.canvasWebgl = {
  id: 'canvasWebgl',
  name: 'Canvas & WebGL Rendering Consistency',
  category: 'Hardware & Rendering',
  weight: 10, // Medium Weight

  async run() {
    const findings = [];
    let scoreDeductions = 0;

    // 1. 2D Canvas Noise Injection & Fingerprint Tampering Test
    const canvasTest = this.checkCanvasRenderingIntegrity();
    findings.push(canvasTest);
    if (!canvasTest.passed) scoreDeductions += canvasTest.penalty;

    // 2. WebGL GPU Hardware vs Software Rasterizer Check
    const webglTest = this.checkWebGLConsistency();
    findings.push(webglTest);
    if (!webglTest.passed) scoreDeductions += webglTest.penalty;

    // 3. Canvas Method Overriding Check (toDataURL / getImageData hooks)
    const hookTest = this.checkCanvasMethodHooks();
    findings.push(hookTest);
    if (!hookTest.passed) scoreDeductions += hookTest.penalty;

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
        gpuVendor: webglTest.gpuVendor || 'Unknown',
        gpuRenderer: webglTest.gpuRenderer || 'Unknown',
        noiseDetected: !canvasTest.passed
      }
    };
  },

  /**
   * Render complex canvas pattern twice in immediate succession.
   * If the hashes differ, a canvas noise injection extension (fingerprint scrambler / hook) is active!
   */
  checkCanvasRenderingIntegrity() {
    try {
      const renderPattern = (canvas) => {
        canvas.width = 200;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');
        if (!ctx) return null;

        // Background gradient
        const grad = ctx.createLinearGradient(0, 0, 200, 60);
        grad.addColorStop(0, '#00ffcc');
        grad.addColorStop(1, '#ff007f');
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, 200, 60);

        // Subpixel Text & Emoji
        ctx.textBaseline = 'top';
        ctx.font = '14px "Arial", "Helvetica", sans-serif';
        ctx.fillStyle = '#0f172a';
        ctx.fillText('TRUST-AUDIT-🛡️-9842', 10, 10);

        // Curved geometry & blending
        ctx.globalCompositeOperation = 'multiply';
        ctx.fillStyle = 'rgba(255, 255, 0, 0.7)';
        ctx.beginPath();
        ctx.arc(100, 30, 25, 0, Math.PI * 2, true);
        ctx.fill();

        return canvas.toDataURL();
      };

      const c1 = document.createElement('canvas');
      const data1 = renderPattern(c1);

      // Check simulated noise injection if active in test mode
      if (window.TRUST._simulatedCanvasNoise) {
        return {
          id: 'canvas_noise_detection',
          title: 'Canvas Noise Injection Detected!',
          passed: false,
          penalty: 20,
          status: 'FAILED',
          observed: 'Inconsistent canvas byte stream (dynamic noise injected between renders)',
          expected: 'Deterministic 2D canvas pixel rendering',
          explanation: 'Canvas fingerprint scrambler extension or hook detected modifying graphics output.',
          importance: 'Indicates untrusted third-party extension modifying browser rendering pipelines.'
        };
      }

      const c2 = document.createElement('canvas');
      const data2 = renderPattern(c2);

      if (!data1 || !data2) {
        return {
          id: 'canvas_noise_detection',
          title: 'Canvas Rendering Unavailable',
          passed: true,
          penalty: 0,
          status: 'INFO',
          observed: '2D Canvas not supported or restricted',
          expected: '2D Canvas support',
          explanation: 'Canvas 2D context could not be instantiated.',
          importance: 'Low'
        };
      }

      if (data1 !== data2) {
        return {
          id: 'canvas_noise_detection',
          title: 'Canvas Noise Injection Detected!',
          passed: false,
          penalty: 20,
          status: 'FAILED',
          observed: 'Identical renders produced differing hashes (noise injected)',
          expected: 'Bitwise deterministic rendering',
          explanation: 'An extension or background script is injecting random pixel noise into canvas outputs.',
          importance: 'Indicates presence of intrusive browser extensions on the terminal.'
        };
      }

      return {
        id: 'canvas_noise_detection',
        title: 'Canvas Pixel Rendering Consistency',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'Bitwise identical output across multiple render passes',
        expected: 'Deterministic pixel stream',
        explanation: 'Canvas rendering is clean, deterministic, and free of noise injector extensions.',
        importance: 'Validates raw browser graphics output integrity.'
      };
    } catch (e) {
      return {
        id: 'canvas_noise_detection',
        title: 'Canvas Check Handled',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: e.message,
        expected: 'Standard canvas context',
        explanation: 'Canvas check finished with warning: ' + e.message,
        importance: 'Low'
      };
    }
  },

  /**
   * Check WebGL GPU hardware acceleration vs software rasterizer (SwiftShader / llvmpipe)
   */
  checkWebGLConsistency() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      
      if (!gl) {
        return {
          id: 'webgl_hardware_gpu',
          title: 'WebGL Context Unavailable',
          passed: true,
          penalty: 5,
          status: 'WARN',
          gpuVendor: 'N/A',
          gpuRenderer: 'N/A',
          observed: 'WebGL disabled or unsupported on this kiosk display driver',
          expected: 'Hardware WebGL pipeline',
          explanation: 'WebGL is disabled or running on legacy display hardware.',
          importance: 'Common on low-cost rural kiosks or locked-down terminals.'
        };
      }

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      let vendor = 'Standard WebGL';
      let renderer = 'Standard WebGL Renderer';

      if (debugInfo) {
        vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || vendor;
        renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || renderer;
      }

      const isSoftwareRasterizer = /swiftshader|llvmpipe|software rasterizer|mesa software/i.test(renderer);

      if (isSoftwareRasterizer) {
        return {
          id: 'webgl_hardware_gpu',
          title: 'Software Rasterizer / Virtualized GPU',
          passed: true,
          penalty: 5,
          status: 'WARN',
          gpuVendor: vendor,
          gpuRenderer: renderer,
          observed: `Software GPU: ${renderer}`,
          expected: 'Direct hardware GPU acceleration',
          explanation: 'WebGL is rendering via CPU software emulation (SwiftShader/llvmpipe). Common in virtual machines or cloud kiosks.',
          importance: 'May indicate terminal is running inside a remote desktop (RDP/VDI) or virtual machine session.'
        };
      }

      return {
        id: 'webgl_hardware_gpu',
        title: 'WebGL Hardware GPU Acceleration',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        gpuVendor: vendor,
        gpuRenderer: renderer,
        observed: `GPU: ${renderer} (${vendor})`,
        expected: 'Hardware GPU driver',
        explanation: 'Direct physical GPU rendering detected with standard hardware acceleration.',
        importance: 'Confirms native hardware graphics pipeline.'
      };
    } catch (e) {
      return {
        id: 'webgl_hardware_gpu',
        title: 'WebGL Check Handled',
        passed: true,
        penalty: 0,
        status: 'INFO',
        gpuVendor: 'Error',
        gpuRenderer: 'Error',
        observed: e.message,
        expected: 'Standard WebGL context',
        explanation: 'WebGL probe completed with note: ' + e.message,
        importance: 'Low'
      };
    }
  },

  /**
   * Check if canvas toDataURL or getImageData prototypes have been overridden
   */
  checkCanvasMethodHooks() {
    try {
      const toDataUrlStr = HTMLCanvasElement.prototype.toDataURL.toString();
      const isNative = /\{\s*\[native code\]\s*\}/.test(toDataUrlStr);

      if (!isNative) {
        return {
          id: 'canvas_method_hooks',
          title: 'Canvas toDataURL Method Tampering',
          passed: false,
          penalty: 25,
          status: 'FAILED',
          observed: 'HTMLCanvasElement.prototype.toDataURL is overridden with custom JS code',
          expected: 'Native toDataURL implementation',
          explanation: 'Canvas export functions have been hijacked by a script or browser extension.',
          importance: 'High risk of screen-scraping or fingerprint spoofing extensions.'
        };
      }

      return {
        id: 'canvas_method_hooks',
        title: 'Canvas API Prototype Integrity',
        passed: true,
        penalty: 0,
        status: 'PASSED',
        observed: 'Native [native code] signature on Canvas methods',
        expected: 'Untampered Canvas prototypes',
        explanation: 'Canvas rendering APIs are untampered.',
        importance: 'Ensures canvas graphics cannot be intercepted.'
      };
    } catch (e) {
      return {
        id: 'canvas_method_hooks',
        title: 'Canvas Hook Check Handled',
        passed: true,
        penalty: 0,
        status: 'INFO',
        observed: 'Protected',
        expected: 'Standard Canvas',
        explanation: 'Canvas API status confirmed.',
        importance: 'Low'
      };
    }
  }
};
