/**
 * Shamir's Secret Sharing (SSS) over Galois Field GF(256)
 *
 * Used to split the document's symmetric AES-256 key into N guardian shares
 * and reconstruct it using any K shares.
 */

// Irreducible polynomial for GF(256): x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
// The bottom bits are 0x1d (29).
const GF_POLYNOMIAL = 0x1d;

const LOG_TABLE = new Uint8Array(256);
const EXP_TABLE = new Uint8Array(512); // Doubled size to avoid % 255 in gfMultiply

// Statically pre-compute Galois Field Log and Anti-Log (Exp) lookup tables
(function initGFTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    EXP_TABLE[i + 255] = x;
    LOG_TABLE[x] = i;

    let temp = (x << 1) & 0xff;
    if (x & 0x80) {
      temp ^= GF_POLYNOMIAL;
    }
    x = temp;
  }
})();

/**
 * Multiply two numbers in GF(256) using O(1) pre-computed lookup tables
 */
export function gfMultiply(a: number, b: number): number {
  const tempA = a & 0xff;
  const tempB = b & 0xff;
  if (tempA === 0 || tempB === 0) return 0;
  return EXP_TABLE[LOG_TABLE[tempA] + LOG_TABLE[tempB]];
}

/**
 * Find multiplicative inverse of a number in GF(256) using O(1) pre-computed lookup table
 */
export function gfInverse(a: number): number {
  const val = a & 0xff;
  if (val === 0) throw new Error("GF(256) division by zero");
  return EXP_TABLE[255 - LOG_TABLE[val]];
}

/**
 * Split a single byte into N shares with threshold K
 */
function splitByte(secret: number, n: number, k: number): number[] {
  if (k > n) throw new Error("Threshold cannot exceed total shares");
  if (k < 1) throw new Error("Threshold must be at least 1");

  // Coefficients: a_0 is the secret byte, a_1 ... a_{k-1} are random bytes
  const coefficients = new Uint8Array(k);
  coefficients[0] = secret;

  const randomValues = new Uint8Array(k - 1);
  if (typeof window !== "undefined" && window.crypto) {
    window.crypto.getRandomValues(randomValues);
  } else if (typeof globalThis !== "undefined" && globalThis.crypto) {
    globalThis.crypto.getRandomValues(randomValues);
  } else {
    for (let i = 0; i < k - 1; i++) {
      randomValues[i] = Math.floor(Math.random() * 256);
    }
  }
  for (let i = 1; i < k; i++) {
    coefficients[i] = randomValues[i - 1];
  }

  const shares: number[] = [];
  // Calculate y for each x = 1 ... n
  for (let x = 1; x <= n; x++) {
    let y = 0;
    let xPower = 1;
    for (let j = 0; j < k; j++) {
      y ^= gfMultiply(coefficients[j], xPower);
      xPower = gfMultiply(xPower, x);
    }
    shares.push(y);
  }

  return shares;
}

/**
 * Reconstruct a single byte from K shares
 * shares is an array of [x, y] coordinates
 */
function reconstructByte(shares: Array<[number, number]>): number {
  let secret = 0;

  for (let i = 0; i < shares.length; i++) {
    const [xi, yi] = shares[i];
    let lagrange = 1;

    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      const [xj] = shares[j];
      // Formula: Product of (xj / (xj ^ xi))
      const numerator = xj;
      const denominator = xj ^ xi;
      lagrange = gfMultiply(lagrange, gfMultiply(numerator, gfInverse(denominator)));
    }

    secret ^= gfMultiply(yi, lagrange);
  }

  return secret;
}

/**
 * Split a hex secret string (e.g. AES key) into N shares with threshold K.
 * Returns an array of strings in format: "x_coordinate-hex_shares_y"
 */
export function splitSecret(secretHex: string, n: number, k: number): string[] {
  const cleanHex = secretHex.startsWith("0x") ? secretHex.slice(2) : secretHex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error("Secret hex string must have an even length");
  }

  const secretBytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < secretBytes.length; i++) {
    secretBytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }

  const resultShares: string[][] = Array.from({ length: n }, () => []);

  for (let byteIndex = 0; byteIndex < secretBytes.length; byteIndex++) {
    const byteShares = splitByte(secretBytes[byteIndex], n, k);
    for (let shareIndex = 0; shareIndex < n; shareIndex++) {
      const hexVal = byteShares[shareIndex].toString(16).padStart(2, "0");
      resultShares[shareIndex].push(hexVal);
    }
  }

  // Format: "x-hexdata" where x is 1-indexed (1 to n)
  return resultShares.map((shareBytes, idx) => `${idx + 1}-${shareBytes.join("")}`);
}

/**
 * Reconstruct the hex secret string from an array of share strings.
 */
export function reconstructSecret(shareStrings: string[]): string {
  if (shareStrings.length === 0) {
    throw new Error("No shares provided for reconstruction");
  }

  const parsedShares: Array<{ x: number; bytes: Uint8Array }> = shareStrings.map((s) => {
    const parts = s.split("-");
    if (parts.length !== 2) {
      throw new Error(`Invalid share format: ${s}`);
    }
    const x = parseInt(parts[0], 10);
    const hex = parts[1];
    if (Number.isNaN(x) || x < 1) {
      throw new Error(`Invalid x-coordinate in share: ${s}`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return { x, bytes };
  });

  const numBytes = parsedShares[0].bytes.length;
  for (const s of parsedShares) {
    if (s.bytes.length !== numBytes) {
      throw new Error("All shares must have the same length");
    }
  }

  const reconstructedBytes = new Uint8Array(numBytes);

  for (let byteIndex = 0; byteIndex < numBytes; byteIndex++) {
    const coordinates: Array<[number, number]> = parsedShares.map((s) => [
      s.x,
      s.bytes[byteIndex],
    ]);
    reconstructedBytes[byteIndex] = reconstructByte(coordinates);
  }

  return Array.from(reconstructedBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const secretsService = {
  splitSecret,
  reconstructSecret,
};
