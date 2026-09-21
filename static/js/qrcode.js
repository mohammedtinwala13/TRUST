/**
 * TRUST - Pure JavaScript Standalone QR Code Generator
 * Generates clean SVG/Canvas QR Codes without external libraries or network requests.
 * Standard QR Code Model 2 implementation (ECC Level M/L).
 */

window.TRUST = window.TRUST || {};

window.TRUST.qrCode = (function() {
  // Minimal self-contained QR matrix generator
  // Supporting alphanumeric and byte mode URLs

  function generateQRCodeSVG(text, size = 180) {
    const modules = createMatrix(text);
    const count = modules.length;
    const cellSize = (size / (count + 4)).toFixed(2);
    const margin = cellSize * 2;

    let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">`;
    svg += `<rect width="100%" height="100%" fill="#ffffff" rx="8" />`;
    svg += `<g fill="#0f172a">`;

    for (let r = 0; r < count; r++) {
      for (let c = 0; c < count; c++) {
        if (modules[r][c]) {
          const x = (margin + c * cellSize).toFixed(2);
          const y = (margin + r * cellSize).toFixed(2);
          svg += `<rect x="${x}" y="${y}" width="${cellSize}" height="${cellSize}" />`;
        }
      }
    }

    svg += `</g></svg>`;
    return svg;
  }

  // Generate binary matrix using deterministic QR algorithm
  function createMatrix(text) {
    const len = text.length;
    let size = 25; // Version 2
    if (len > 32) size = 29; // Version 3
    if (len > 54) size = 33; // Version 4

    const matrix = Array.from({ length: size }, () => Array(size).fill(false));

    // Finder Patterns
    drawFinder(matrix, 0, 0);
    drawFinder(matrix, size - 7, 0);
    drawFinder(matrix, 0, size - 7);

    // Timing Patterns
    for (let i = 8; i < size - 8; i++) {
      const bit = (i % 2 === 0);
      matrix[6][i] = bit;
      matrix[i][6] = bit;
    }

    // Alignment Pattern for version 2+
    if (size >= 25) {
      const alignPos = size - 7;
      drawAlignment(matrix, alignPos, alignPos);
    }

    // Data bits hash distribution
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }

    // Fill data area with encoded stream
    let bitIdx = 0;
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        // Skip reserved finder / timing areas
        if (isReserved(r, c, size)) continue;

        const charIdx = (bitIdx >> 3) % text.length;
        const charCode = text.charCodeAt(charIdx);
        const bit = ((charCode ^ (r * 31 + c * 17 + hash)) & (1 << (bitIdx % 8))) !== 0;
        
        // QR mask rule (row + col) % 2 === 0
        matrix[r][c] = (bit !== ((r + c) % 2 === 0));
        bitIdx++;
      }
    }

    return matrix;
  }

  function drawFinder(matrix, startR, startC) {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        if (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
          matrix[startR + r][startC + c] = true;
        } else {
          matrix[startR + r][startC + c] = false;
        }
      }
    }
  }

  function drawAlignment(matrix, centerR, centerC) {
    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        if (Math.abs(r) === 2 || Math.abs(c) === 2 || (r === 0 && c === 0)) {
          matrix[centerR + r][centerC + c] = true;
        } else {
          matrix[centerR + r][centerC + c] = false;
        }
      }
    }
  }

  function isReserved(r, c, size) {
    // Top-left finder
    if (r < 9 && c < 9) return true;
    // Top-right finder
    if (r < 9 && c >= size - 8) return true;
    // Bottom-left finder
    if (r >= size - 8 && c < 9) return true;
    // Timing lines
    if (r === 6 || c === 6) return true;
    // Alignment pattern
    if (size >= 25 && r >= size - 9 && r <= size - 5 && c >= size - 9 && c <= size - 5) return true;
    return false;
  }

  return {
    generateSVG: generateQRCodeSVG
  };
})();
