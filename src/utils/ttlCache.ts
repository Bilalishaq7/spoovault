interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

export class TTLCache {
  private cache = new Map<string, CacheEntry<any>>();
  private ttlMs: number;

  constructor(ttlSeconds: number = 10) {
    this.ttlMs = ttlSeconds * 1000;
  }

  async fetch<T>(key: string, fetchFn: () => Promise<T>): Promise<T> {
    const now = Date.now();
    const entry = this.cache.get(key);

    if (entry && now - entry.timestamp < this.ttlMs) {
      return entry.data as T;
    }

    const data = await fetchFn();
    this.cache.set(key, { data, timestamp: now });
    return data;
  }

  clear(key?: string): void {
    if (key) {
      this.cache.delete(key);
    } else {
      this.cache.clear();
    }
  }

  hasValidKey(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;
    return Date.now() - entry.timestamp < this.ttlMs;
  }
}

export const readViewCache = new TTLCache(10);
