import crypto from "crypto";

export interface CrossChainPayload {
  vaultGID: string;
  guardian: string;
  approvalType: number;
  timestamp: number;
  signature?: string;
}

export class CrossChainRelayerService {
  private processedHashes: Set<string> = new Set();

  /**
   * Encodes and cryptographically signs cross-chain approval payload
   */
  static signPayload(payload: CrossChainPayload, secretKey: string): CrossChainPayload {
    const rawData = `${payload.vaultGID}:${payload.guardian}:${payload.approvalType}:${payload.timestamp}`;
    const signature = crypto.createHmac("sha256", secretKey).update(rawData).digest("hex");
    return { ...payload, signature };
  }

  /**
   * Verifies signature and checks for replay protection
   */
  processMessage(payload: CrossChainPayload, secretKey: string): { success: boolean; messageHash: string } {
    const rawData = `${payload.vaultGID}:${payload.guardian}:${payload.approvalType}:${payload.timestamp}`;
    const expectedSig = crypto.createHmac("sha256", secretKey).update(rawData).digest("hex");

    if (payload.signature !== expectedSig) {
      throw new Error("Invalid payload signature");
    }

    const messageHash = crypto.createHash("sha256").update(`${rawData}:${payload.signature}`).digest("hex");

    if (this.processedHashes.has(messageHash)) {
      throw new Error("Replay attack detected: Message already processed");
    }

    this.processedHashes.add(messageHash);
    return { success: true, messageHash };
  }
}
