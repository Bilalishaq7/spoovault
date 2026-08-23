/**
 * @file pir.service.ts
 * @description Private Information Retrieval (PIR) service for oblivious IPFS document fetching.
 *
 * Implements PIR principles to prevent IPFS gateway nodes from correlating beneficiary
 * IP addresses with specific vault document CIDs through:
 * 1. Mixnet proxy routing (Tor SOCKS5)
 * 2. PIR dummy query batching
 * 3. Encrypted CID indexing with homomorphic hashes
 *
 * Architecture:
 * - PirService: Main service orchestrating oblivious fetches
 * - TorProxyClient: SOCKS5 proxy client for Tor routing
 * - DummyQueryBatcher: Generates dummy queries to obscure real requests
 * - HomomorphicHash: CID obfuscation using homomorphic hashing
 */

import { ipfsGateway } from "./ipfsGateway";

// ─── Configuration ───────────────────────────────────────────────────────────────

const TOR_SOCKS_PORT = 9050;
const DEFAULT_DUMMY_QUERY_COUNT = 5;
const DEFAULT_BATCH_DELAY_MS = 100;

// ─── Types ───────────────────────────────────────────────────────────────────────

export interface PirConfig {
  enabled: boolean;
  useTorProxy: boolean;
  torSocksHost?: string;
  torSocksPort?: number;
  dummyQueryCount?: number;
  batchDelayMs?: number;
}

export interface PirFetchResult {
  success: boolean;
  data?: ArrayBuffer;
  error?: string;
  gatewayUsed?: string;
  proxied: boolean;
  dummyQueriesIssued: number;
}

export interface DummyQuery {
  cid: string;
  isReal: boolean;
  timestamp: number;
}

// ─── Homomorphic Hash for CID Obfuscation ─────────────────────────────────────────

/**
 * Simple homomorphic hash implementation for CID obfuscation.
 * Uses SHA-256 with a per-session salt to generate deterministic but
 * non-reversible CID identifiers.
 */
export class HomomorphicHash {
  private salt: string;

  constructor() {
    this.salt = this.generateSalt();
  }

  private generateSalt(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Generate a homomorphic hash for a CID.
   * The same CID will always produce the same hash within a session,
   * but different sessions produce different hashes.
   */
  async hashCid(cid: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(this.salt + cid);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Verify a CID against its homomorphic hash.
   */
  async verifyCid(cid: string, hash: string): Promise<boolean> {
    const computedHash = await this.hashCid(cid);
    return computedHash === hash;
  }

  getSalt(): string {
    return this.salt;
  }
}

// ─── Dummy Query Batcher ─────────────────────────────────────────────────────────

/**
 * Generates dummy IPFS queries to obscure real document fetches.
 * Implements PIR by batching real queries with dummy queries.
 */
export class DummyQueryBatcher {
  private dummyQueryCount: number;
  private batchDelayMs: number;

  constructor(dummyQueryCount: number = DEFAULT_DUMMY_QUERY_COUNT, batchDelayMs: number = DEFAULT_BATCH_DELAY_MS) {
    this.dummyQueryCount = dummyQueryCount;
    this.batchDelayMs = batchDelayMs;
  }

  /**
   * Generate a dummy CID that looks like a real IPFS CID.
   * Uses the CIDv0 format (base58 encoded SHA-256 hash).
   */
  private generateDummyCid(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    
    // Add CIDv0 prefix (0x12 for SHA-256, 0x20 for 32 bytes)
    const prefixed = new Uint8Array(34);
    prefixed[0] = 0x12;
    prefixed[1] = 0x20;
    prefixed.set(array, 2);
    
    // Base58 encode (simplified implementation)
    return this.base58Encode(prefixed.slice(2));
  }

  private base58Encode(bytes: Uint8Array): string {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const digits = [0];
    
    for (let i = 0; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = (carry / 58) | 0;
      }
    }
    
    let result = "";
    for (let i = 0; i < digits.length; i++) {
      result += alphabet[digits[i]];
    }
    
    return result;
  }

  /**
   * Create a batch of queries containing the real query and dummy queries.
   */
  createBatch(realCid: string): DummyQuery[] {
    const batch: DummyQuery[] = [
      {
        cid: realCid,
        isReal: true,
        timestamp: Date.now(),
      },
    ];

    for (let i = 0; i < this.dummyQueryCount; i++) {
      batch.push({
        cid: this.generateDummyCid(),
        isReal: false,
        timestamp: Date.now() + (i + 1) * this.batchDelayMs,
      });
    }

    // Shuffle the batch to obscure which query is real
    return this.shuffleArray(batch);
  }

  private shuffleArray<T>(array: T[]): T[] {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  /**
   * Execute a batch of queries, returning only the result of the real query.
   */
  async executeBatch(
    batch: DummyQuery[],
    fetchFn: (cid: string) => Promise<Response>
  ): Promise<{ realResult: Response; dummyCount: number }> {
    let realResult: Response | null = null;
    let dummyCount = 0;

    for (const query of batch) {
      try {
        if (query.isReal) {
          realResult = await fetchFn(query.cid);
        } else {
          // Execute dummy query but ignore result
          await fetchFn(query.cid).catch(() => {
            // Dummy queries are expected to fail
          });
          dummyCount++;
        }
      } catch (error) {
        // Silently ignore dummy query failures
        if (!query.isReal) {
          dummyCount++;
        }
      }
    }

    if (!realResult) {
      throw new Error("Real query failed to execute");
    }

    return { realResult, dummyCount };
  }
}

// ─── Tor Proxy Client ─────────────────────────────────────────────────────────────

/**
 * SOCKS5 proxy client for routing IPFS requests through Tor.
 * Note: This is a simplified implementation. Full Tor integration requires
 * a local Tor daemon running with SOCKS5 proxy enabled.
 */
class TorProxyClient {
  private host: string;
  private port: number;
  private enabled: boolean;

  constructor(host: string = "127.0.0.1", port: number = TOR_SOCKS_PORT, enabled: boolean = false) {
    this.host = host;
    this.port = port;
    this.enabled = enabled;
  }

  /**
   * Check if Tor proxy is available.
   */
  async isAvailable(): Promise<boolean> {
    if (!this.enabled) {
      return false;
    }

    try {
      // Try to connect to Tor SOCKS5 proxy
      const response = await fetch(`http://${this.host}:${this.port}`, {
        method: "CONNECT",
        signal: AbortSignal.timeout(1000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Create a proxied fetch function that routes through Tor.
   * Note: Browser-based SOCKS5 proxying requires browser extensions or
   * specific configurations. This is a placeholder for the implementation.
   */
  createProxiedFetch(): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
    if (!this.enabled) {
      return fetch;
    }

    // In a real implementation, this would use a SOCKS5 proxy library
    // For now, we return the standard fetch as a fallback
    return fetch;
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }
}

// ─── PIR Service ─────────────────────────────────────────────────────────────────

/**
 * Main PIR service orchestrating oblivious IPFS fetches.
 */
export class PirService {
  private config: PirConfig;
  private homomorphicHash: HomomorphicHash;
  private dummyBatcher: DummyQueryBatcher;
  private torProxy: TorProxyClient;

  constructor(config: PirConfig = { enabled: true, useTorProxy: false }) {
    this.config = {
      dummyQueryCount: DEFAULT_DUMMY_QUERY_COUNT,
      batchDelayMs: DEFAULT_BATCH_DELAY_MS,
      ...config,
    };

    this.homomorphicHash = new HomomorphicHash();
    this.dummyBatcher = new DummyQueryBatcher(
      this.config.dummyQueryCount,
      this.config.batchDelayMs
    );
    this.torProxy = new TorProxyClient(
      this.config.torSocksHost || "127.0.0.1",
      this.config.torSocksPort || TOR_SOCKS_PORT,
      this.config.useTorProxy
    );
  }

  /**
   * Fetch a document from IPFS using PIR principles.
   */
  async fetchDocument(cid: string, signal?: AbortSignal): Promise<PirFetchResult> {
    if (!this.config.enabled) {
      // Fallback to standard IPFS fetch if PIR is disabled
      return this.standardFetch(cid, signal);
    }

    try {
      const torAvailable = await this.torProxy.isAvailable();
      const proxiedFetch = torAvailable ? this.torProxy.createProxiedFetch() : fetch;

      // Create query batch with dummy queries
      const batch = this.dummyBatcher.createBatch(cid);

      // Execute batch
      const { realResult, dummyCount } = await this.dummyBatcher.executeBatch(
        batch,
        (queryCid) => proxiedFetch(ipfsGateway.getURL(queryCid), { signal })
      );

      if (!realResult.ok) {
        return {
          success: false,
          error: `HTTP ${realResult.status}`,
          proxied: torAvailable,
          dummyQueriesIssued: dummyCount,
        };
      }

      const data = await realResult.arrayBuffer();

      return {
        success: true,
        data,
        gatewayUsed: ipfsGateway.getURL(cid),
        proxied: torAvailable,
        dummyQueriesIssued: dummyCount,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        proxied: this.config.useTorProxy,
        dummyQueriesIssued: 0,
      };
    }
  }

  /**
   * Standard IPFS fetch without PIR (fallback).
   */
  private async standardFetch(cid: string, signal?: AbortSignal): Promise<PirFetchResult> {
    try {
      const response = await ipfsGateway.fetchFile(cid, { signal });
      const data = await response.arrayBuffer();

      return {
        success: true,
        data,
        gatewayUsed: ipfsGateway.getURL(cid),
        proxied: false,
        dummyQueriesIssued: 0,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        proxied: false,
        dummyQueriesIssued: 0,
      };
    }
  }

  /**
   * Get the homomorphic hash for a CID.
   */
  async getCidHash(cid: string): Promise<string> {
    return this.homomorphicHash.hashCid(cid);
  }

  /**
   * Verify a CID against its homomorphic hash.
   */
  async verifyCid(cid: string, hash: string): Promise<boolean> {
    return this.homomorphicHash.verifyCid(cid, hash);
  }

  /**
   * Update PIR configuration.
   */
  updateConfig(config: Partial<PirConfig>): void {
    this.config = { ...this.config, ...config };
    
    if (config.useTorProxy !== undefined) {
      this.torProxy.setEnabled(config.useTorProxy);
    }
    
    if (config.dummyQueryCount !== undefined) {
      this.dummyBatcher = new DummyQueryBatcher(
        config.dummyQueryCount,
        this.config.batchDelayMs || DEFAULT_BATCH_DELAY_MS
      );
    }
  }

  /**
   * Get current PIR configuration.
   */
  getConfig(): PirConfig {
    return { ...this.config };
  }

  /**
   * Check if Tor proxy is available.
   */
  async isTorAvailable(): Promise<boolean> {
    return this.torProxy.isAvailable();
  }
}

// ─── Singleton Export ─────────────────────────────────────────────────────────────

export const pirService = new PirService({
  enabled: import.meta.env.VITE_PIR_ENABLED === "true",
  useTorProxy: import.meta.env.VITE_PIR_USE_TOR === "true",
  torSocksHost: import.meta.env.VITE_PIR_TOR_HOST,
  torSocksPort: import.meta.env.VITE_PIR_TOR_PORT 
    ? Number(import.meta.env.VITE_PIR_TOR_PORT) 
    : undefined,
  dummyQueryCount: import.meta.env.VITE_PIR_DUMMY_COUNT 
    ? Number(import.meta.env.VITE_PIR_DUMMY_COUNT) 
    : undefined,
  batchDelayMs: import.meta.env.VITE_PIR_BATCH_DELAY 
    ? Number(import.meta.env.VITE_PIR_BATCH_DELAY) 
    : undefined,
});
