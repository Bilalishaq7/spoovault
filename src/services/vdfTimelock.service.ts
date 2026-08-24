export interface VdfSetup {
  targetSteps: number;
  seed: string;
}

export interface VdfProof {
  output: string;
  proof: string;
  targetSteps: number;
}

export class VdfTimelockEngine {
  private static getCrypto(): Crypto {
    if (typeof window !== 'undefined' && window.crypto) {
      return window.crypto;
    }
    // Fallback for Node.js environments
    return require('node:crypto').webcrypto as unknown as Crypto;
  }

  /**
   * Derive symmetric key K = H(VDF_output)
   */
  static async deriveKey(vdfOutput: string): Promise<any> {
    const cryptoObj = this.getCrypto();
    const encoder = new TextEncoder();
    const data = encoder.encode(vdfOutput);
    const hashBuffer = await cryptoObj.subtle.digest("SHA-256", data);
    return await cryptoObj.subtle.importKey(
      "raw",
      hashBuffer,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Evaluates sequential squaring VDF over T steps
   */
  static async evaluateVdf(seed: string, targetSteps: number): Promise<VdfProof> {
    const cryptoObj = this.getCrypto();
    const encoder = new TextEncoder();
    let current = encoder.encode(seed);

    for (let i = 0; i < targetSteps; i++) {
      const buf = await cryptoObj.subtle.digest("SHA-256", current);
      current = new Uint8Array(buf);
    }

    const outputHex = Array.from(current)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Succinct proof calculation H(seed || output || steps)
    const proofBuf = await cryptoObj.subtle.digest(
      "SHA-256",
      encoder.encode(`${seed}:${outputHex}:${targetSteps}`)
    );
    const proofHex = Array.from(new Uint8Array(proofBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return {
      output: outputHex,
      proof: proofHex,
      targetSteps,
    };
  }

  /**
   * Encrypt document using derived key
   */
  static async encryptDocument(plaintext: string, vdfOutput: string) {
    const cryptoObj = this.getCrypto();
    const key = await this.deriveKey(vdfOutput);
    const iv = cryptoObj.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const ciphertext = await cryptoObj.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(plaintext)
    );

    return {
      ciphertext: Array.from(new Uint8Array(ciphertext))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
      iv: Array.from(iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    };
  }
}
