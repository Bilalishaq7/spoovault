export const SOROBAN_EVENT_TOPICS = ["VaultCreated", "GuardianAdded", "AccessRequested"] as const;
export type SorobanEventTopic = (typeof SOROBAN_EVENT_TOPICS)[number];

export interface IndexedSorobanEvent {
  id: string;
  cursor: string;
  contractId: string;
  ledger: number;
  ledgerClosedAt: string;
  topic: SorobanEventTopic;
  rawTopics: string[];
  value: unknown;
}

type RpcEvent = {
  id?: string;
  pagingToken?: string;
  contractId?: string;
  ledger?: number;
  ledgerClosedAt?: string;
  topic?: unknown[];
  value?: unknown;
};

type Listener = (event: IndexedSorobanEvent) => void;
const DB_NAME = "spoovault-soroban-events";
const STORE = "events";

function topicFrom(rawTopics: unknown[] = []): SorobanEventTopic | null {
  const text = rawTopics.map(String).join(" ");
  return SOROBAN_EVENT_TOPICS.find((topic) => text.includes(topic)) ?? null;
}

export function parseSorobanEvent(raw: RpcEvent, fallbackContractId: string): IndexedSorobanEvent | null {
  const rawTopics = (raw.topic ?? []).map(String);
  const topic = topicFrom(rawTopics);
  const cursor = raw.pagingToken ?? raw.id;
  if (!topic || !cursor) return null;
  return {
    id: raw.id ?? cursor,
    cursor,
    contractId: raw.contractId ?? fallbackContractId,
    ledger: Number(raw.ledger ?? 0),
    ledgerClosedAt: raw.ledgerClosedAt ?? new Date().toISOString(),
    topic,
    rawTopics,
    value: raw.value,
  };
}

class EventStore {
  private memory = new Map<string, IndexedSorobanEvent>();
  private dbPromise: Promise<IDBDatabase> | null = null;

  private db() {
    if (typeof indexedDB === "undefined") return Promise.reject(new Error("IndexedDB unavailable"));
    if (!this.dbPromise) this.dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: "id" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return this.dbPromise;
  }

  async put(event: IndexedSorobanEvent) {
    this.memory.set(event.id, event);
    try {
      const db = await this.db();
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(event);
        tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
      });
    } catch { /* SSR/private-mode fallback remains in memory. */ }
  }
}

export class SorobanEventIndexer {
  private running = false;
  private cursor?: string;
  private timer?: ReturnType<typeof setTimeout>;
  private failures = 0;
  private rpcUrl = "";
  private contractId = "";
  private listeners = new Set<Listener>();
  private socket?: WebSocket;
  private store = new EventStore();

  start(rpcUrl: string, contractId: string, relayUrl = import.meta.env.VITE_SOROBAN_EVENT_RELAY_URL as string | undefined) {
    this.stop(); this.running = true; this.rpcUrl = rpcUrl; this.contractId = contractId;
    if (relayUrl) this.connectRelay(relayUrl);
    void this.poll();
  }
  stop() { this.running = false; if (this.timer) clearTimeout(this.timer); this.timer = undefined; this.socket?.close(); this.socket = undefined; }
  subscribe(listener: Listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }

  private connectRelay(url: string) {
    if (typeof WebSocket === "undefined") return;
    this.socket = new WebSocket(url);
    this.socket.onmessage = (message) => {
      try { const event = parseSorobanEvent(JSON.parse(message.data), this.contractId); if (event) void this.publish(event); } catch { /* Ignore malformed relay payloads. */ }
    };
  }
  private delay() { return this.failures ? Math.min(30_000, 500 * 2 ** Math.min(this.failures, 6)) : 250; }
  private async poll(): Promise<void> {
    if (!this.running) return;
    try {
      const params: Record<string, unknown> = {
        filters: [{ type: "contract", contractIds: [this.contractId] }],
        pagination: { limit: 100, ...(this.cursor ? { cursor: this.cursor } : {}) },
      };
      const response = await fetch(this.rpcUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getEvents", params }) });
      if (!response.ok) throw new Error(`Soroban RPC ${response.status}`);
      const body = await response.json(); if (body.error) throw new Error(body.error.message);
      for (const raw of body.result?.events ?? []) { const event = parseSorobanEvent(raw, this.contractId); if (event) { this.cursor = event.cursor; await this.publish(event); } }
      this.failures = 0;
    } catch (error) { this.failures += 1; console.warn("Soroban event indexer will retry", error); }
    if (this.running) this.timer = setTimeout(() => void this.poll(), this.delay());
  }
  private async publish(event: IndexedSorobanEvent) {
    await this.store.put(event);
    this.listeners.forEach((listener) => listener(event));
    window.dispatchEvent(new CustomEvent("spoovault:soroban:event", { detail: event }));
    if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(JSON.stringify(event));
  }
}

export const sorobanEventIndexer = new SorobanEventIndexer();
