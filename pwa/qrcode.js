/**
 * Minimal QR Code Generator — Pure JS, zero dependencies.
 * Supports byte mode, error correction level M, versions 1-10.
 * Public domain / MIT — use freely.
 */

(function(global) {
  'use strict';

  // GF(256) with polynomial 0x11d
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x = (x << 1) ^ (x & 128 ? 0x11d : 0);
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  function gfMul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }

  function polyMul(a, b) {
    const r = new Uint8Array(a.length + b.length - 1);
    for (let i = 0; i < a.length; i++)
      for (let j = 0; j < b.length; j++)
        r[i + j] ^= gfMul(a[i], b[j]);
    return r;
  }

  function polyRem(dividend, divisor) {
    const result = new Uint8Array(dividend);
    for (let i = 0; i <= result.length - divisor.length; i++) {
      if (!result[i]) continue;
      const coef = result[i];
      for (let j = 0; j < divisor.length; j++)
        result[i + j] ^= gfMul(divisor[j], coef);
    }
    return result.slice(dividend.length - divisor.length + 1);
  }

  function genPoly(n) {
    let g = new Uint8Array([1]);
    for (let i = 0; i < n; i++)
      g = polyMul(g, new Uint8Array([1, EXP[i]]));
    return g;
  }

  // Version info: [version, totalCodewords, ecCodewordsPerBlock, numBlocks]
  // EC level M only
  const VERSIONS = [
    null,
    [1, 26, 10, 1],    // v1: 16 data bytes
    [2, 44, 16, 1],    // v2: 28
    [3, 70, 26, 1],    // v3: 44
    [4, 100, 18, 2],   // v4: 64
    [5, 134, 24, 2],   // v5: 86
    [6, 172, 16, 4],   // v6: 108  (corrected)
    [7, 196, 18, 4],   // v7: 124  (corrected)
    [8, 242, 22, 4],   // v8: 154  (corrected)
    [9, 292, 22, 4],   // v9: 182  (corrected)
    [10, 346, 26, 4],  // v10: 216 (corrected)
  ];

  function chooseVersion(dataLen) {
    for (let v = 1; v <= 10; v++) {
      const [, total, ecPerBlock, numBlocks] = VERSIONS[v];
      const dataCapacity = total - ecPerBlock * numBlocks;
      // byte mode: 4 bits mode + 8 bits length + data + terminator
      const needed = Math.ceil((4 + 8 + dataLen * 8 + 4) / 8);
      if (needed <= dataCapacity) return v;
    }
    return 10; // max supported
  }

  function encodeData(text, version) {
    const [, total, ecPerBlock, numBlocks] = VERSIONS[version];
    const dataCapacity = total - ecPerBlock * numBlocks;

    const bits = [];
    function pushBits(val, len) {
      for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
    }

    // Mode: byte (0100)
    pushBits(4, 4);
    // Length
    const charCountBits = version <= 9 ? 8 : 16;
    pushBits(text.length, charCountBits);
    // Data
    for (let i = 0; i < text.length; i++) pushBits(text.charCodeAt(i) & 0xFF, 8);
    // Terminator
    pushBits(0, Math.min(4, dataCapacity * 8 - bits.length));

    // Pad to byte boundary
    while (bits.length % 8) bits.push(0);

    // Pad to capacity
    const padBytes = [0xEC, 0x11];
    let padIdx = 0;
    while (bits.length < dataCapacity * 8) {
      pushBits(padBytes[padIdx % 2], 8);
      padIdx++;
    }

    // Convert to bytes
    const dataBytes = new Uint8Array(dataCapacity);
    for (let i = 0; i < dataCapacity; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | (bits[i * 8 + j] || 0);
      dataBytes[i] = b;
    }

    // Split into blocks and add EC
    const blockDataSize = Math.floor(dataCapacity / numBlocks);
    const remainder = dataCapacity % numBlocks;
    const g = genPoly(ecPerBlock);
    const allData = [];
    const allEc = [];
    let offset = 0;

    for (let b = 0; b < numBlocks; b++) {
      const size = blockDataSize + (b >= numBlocks - remainder ? 1 : 0);
      const block = dataBytes.slice(offset, offset + size);
      offset += size;
      allData.push(block);

      const padded = new Uint8Array(size + ecPerBlock);
      padded.set(block);
      allEc.push(polyRem(padded, g));
    }

    // Interleave
    const result = [];
    const maxDataLen = blockDataSize + (remainder ? 1 : 0);
    for (let i = 0; i < maxDataLen; i++)
      for (let b = 0; b < numBlocks; b++)
        if (i < allData[b].length) result.push(allData[b][i]);
    for (let i = 0; i < ecPerBlock; i++)
      for (let b = 0; b < numBlocks; b++)
        result.push(allEc[b][i]);

    return new Uint8Array(result);
  }

  function createMatrix(version) {
    const size = version * 4 + 17;
    const matrix = Array.from({length: size}, () => new Int8Array(size)); // 0=unset, 1=black, -1=white
    const reserved = Array.from({length: size}, () => new Uint8Array(size));

    function setModule(r, c, val) {
      if (r >= 0 && r < size && c >= 0 && c < size) {
        matrix[r][c] = val ? 1 : -1;
        reserved[r][c] = 1;
      }
    }

    // Finder patterns
    function finder(row, col) {
      for (let dr = -1; dr <= 7; dr++)
        for (let dc = -1; dc <= 7; dc++) {
          const r = row + dr, c = col + dc;
          if (r < 0 || r >= size || c < 0 || c >= size) continue;
          const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
          const inMiddle = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
          const onBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
          setModule(r, c, inMiddle || (inOuter && onBorder));
        }
    }
    finder(0, 0);
    finder(0, size - 7);
    finder(size - 7, 0);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
      setModule(6, i, i % 2 === 0);
      setModule(i, 6, i % 2 === 0);
    }

    // Alignment pattern (version >= 2)
    if (version >= 2) {
      const pos = [6, version * 4 + 10]; // simplified for v2-10
      for (const r of pos)
        for (const c of pos) {
          if (reserved[r]?.[c]) continue;
          for (let dr = -2; dr <= 2; dr++)
            for (let dc = -2; dc <= 2; dc++) {
              const val = Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0);
              setModule(r + dr, c + dc, val);
            }
        }
    }

    // Reserve format info areas
    for (let i = 0; i < 8; i++) {
      if (!reserved[8]?.[i]) setModule(8, i, false);
      if (!reserved[i]?.[8]) setModule(i, 8, false);
      if (!reserved[8]?.[size - 1 - i]) setModule(8, size - 1 - i, false);
      if (!reserved[size - 1 - i]?.[8]) setModule(size - 1 - i, 8, false);
    }
    setModule(8, 8, false);
    // Dark module
    setModule(size - 8, 8, true);

    return { matrix, reserved, size };
  }

  function placeData(matrix, reserved, size, data) {
    let bitIdx = 0;
    let upward = true;

    for (let col = size - 1; col >= 0; col -= 2) {
      if (col === 6) col = 5; // skip timing column
      const rows = upward ? [...Array(size).keys()].reverse() : [...Array(size).keys()];
      for (const row of rows) {
        for (let dc = 0; dc <= 1; dc++) {
          const c = col - dc;
          if (c < 0 || reserved[row][c]) continue;
          const bit = bitIdx < data.length * 8 ? (data[Math.floor(bitIdx / 8)] >> (7 - bitIdx % 8)) & 1 : 0;
          matrix[row][c] = bit ? 1 : -1;
          bitIdx++;
        }
      }
      upward = !upward;
    }
  }

  function applyMask(matrix, reserved, size, maskId) {
    const maskFn = [
      (r,c) => (r+c)%2===0,
      (r,c) => r%2===0,
      (r,c) => c%3===0,
      (r,c) => (r+c)%3===0,
      (r,c) => (Math.floor(r/2)+Math.floor(c/3))%2===0,
      (r,c) => (r*c)%2+(r*c)%3===0,
      (r,c) => ((r*c)%2+(r*c)%3)%2===0,
      (r,c) => ((r+c)%2+(r*c)%3)%2===0,
    ][maskId];

    for (let r = 0; r < size; r++)
      for (let c = 0; c < size; c++)
        if (!reserved[r][c] && maskFn(r, c))
          matrix[r][c] = matrix[r][c] === 1 ? -1 : 1;
  }

  function writeFormatInfo(matrix, size, maskId) {
    // EC level M = 00, mask pattern 3 bits
    const ecMask = (0b00 << 3) | maskId;
    // BCH(15,5) encoding
    let fmt = ecMask << 10;
    let gen = 0b10100110111;
    for (let i = 14; i >= 10; i--)
      if (fmt & (1 << i)) fmt ^= gen << (i - 10);
    fmt = ((ecMask << 10) | fmt) ^ 0b101010000010010;

    // Place format bits
    const bits = [];
    for (let i = 14; i >= 0; i--) bits.push((fmt >> i) & 1);

    // Around top-left finder
    const positions1 = [[8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],[7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]];
    // Around other finders
    const positions2 = [];
    for (let i = 0; i < 7; i++) positions2.push([size-1-i, 8]);
    positions2.push([size-8, 8]);
    for (let i = 0; i < 7; i++) positions2.push([8, size-7+i]);

    for (let i = 0; i < 15; i++) {
      const val = bits[i] ? 1 : -1;
      if (positions1[i]) matrix[positions1[i][0]][positions1[i][1]] = val;
      if (positions2[i]) matrix[positions2[i][0]][positions2[i][1]] = val;
    }
  }

  /**
   * Generate a QR code matrix from a text string.
   * Returns {matrix: boolean[][], size: number}
   * matrix[row][col] = true means black module.
   */
  function makeQR(text) {
    const version = chooseVersion(text.length);
    const data = encodeData(text, version);
    const { matrix, reserved, size } = createMatrix(version);
    placeData(matrix, reserved, size, data);

    // Apply mask 0 (simplest, generally good)
    applyMask(matrix, reserved, size, 0);
    writeFormatInfo(matrix, size, 0);

    // Convert to boolean matrix
    const result = [];
    for (let r = 0; r < size; r++) {
      result[r] = [];
      for (let c = 0; c < size; c++)
        result[r][c] = matrix[r][c] === 1;
    }
    return { matrix: result, size };
  }

  /**
   * Render a QR code matrix to a canvas.
   */
  function renderQRToCanvas(qr, canvas, padding) {
    padding = padding || 4;
    const ctx = canvas.getContext('2d');
    const totalModules = qr.size + padding * 2;
    const moduleSize = Math.floor(Math.min(canvas.width, canvas.height) / totalModules);
    const offset = Math.floor((canvas.width - totalModules * moduleSize) / 2);

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#000000';
    for (let r = 0; r < qr.size; r++)
      for (let c = 0; c < qr.size; c++)
        if (qr.matrix[r][c])
          ctx.fillRect(
            offset + (c + padding) * moduleSize,
            offset + (r + padding) * moduleSize,
            moduleSize, moduleSize
          );
  }

  // Export
  global.makeQR = makeQR;
  global.renderQRToCanvas = renderQRToCanvas;

})(typeof window !== 'undefined' ? window : this);
