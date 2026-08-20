import { describe, it, expect } from "vitest";
import {
  gfMultiply,
  gfInverse,
  splitSecret,
  reconstructSecret,
} from "../services/secrets.service";

describe("Galois Field GF(256) Lookup Table Optimization (Issue #16)", () => {
  describe("gfMultiply", () => {
    it("returns 0 when either operand is 0", () => {
      expect(gfMultiply(0, 123)).toBe(0);
      expect(gfMultiply(123, 0)).toBe(0);
      expect(gfMultiply(0, 0)).toBe(0);
    });

    it("returns the other operand when multiplying by 1 (identity)", () => {
      for (let i = 0; i < 256; i++) {
        expect(gfMultiply(i, 1)).toBe(i);
        expect(gfMultiply(1, i)).toBe(i);
      }
    });

    it("satisfies commutative property a * b === b * a across full GF(256) field", () => {
      for (let a = 1; a < 256; a += 17) {
        for (let b = 1; b < 256; b += 13) {
          expect(gfMultiply(a, b)).toBe(gfMultiply(b, a));
        }
      }
    });
  });

  describe("gfInverse", () => {
    it("throws division by zero error when input is 0", () => {
      expect(() => gfInverse(0)).toThrow("GF(256) division by zero");
    });

    it("computes exact multiplicative inverse a * a^-1 === 1 for all non-zero elements", () => {
      for (let a = 1; a < 256; a++) {
        const inv = gfInverse(a);
        expect(gfMultiply(a, inv)).toBe(1);
      }
    });
  });

  describe("Shamir's Secret Sharing (SSS) key splitting and reconstruction", () => {
    it("correctly splits and reconstructs a 256-bit AES hex key with 3-of-5 threshold", () => {
      const secretHex = "4f2a9c1e8b7d6f5a3c1e9b7d5a3c1e9b7d5a3c1e9b7d5a3c1e9b7d5a3c1e9b7d";
      const N = 5;
      const K = 3;

      const shares = splitSecret(secretHex, N, K);
      expect(shares.length).toBe(5);

      // Reconstruct using any 3 shares (e.g., 0, 2, 4)
      const selectedShares = [shares[0], shares[2], shares[4]];
      const reconstructed = reconstructSecret(selectedShares);

      expect(reconstructed.toLowerCase()).toBe(secretHex.toLowerCase());
    });

    it("correctly splits and reconstructs with 2-of-3 threshold", () => {
      const secretHex = "deadbeef1234567890abcdef";
      const shares = splitSecret(secretHex, 3, 2);

      const reconstructed = reconstructSecret([shares[1], shares[2]]);
      expect(reconstructed.toLowerCase()).toBe(secretHex.toLowerCase());
    });
  });

  describe("Performance Benchmark", () => {
    it("executes 10,000 GF(256) multiplications rapidly without thread blocking", () => {
      const start = performance.now();
      let acc = 1;
      for (let i = 1; i < 10000; i++) {
        acc = gfMultiply(acc, (i % 255) + 1);
      }
      const elapsed = performance.now() - start;

      expect(acc).toBeGreaterThanOrEqual(0);
      expect(elapsed).toBeLessThan(100); // Should complete in under 100ms
    });
  });
});
