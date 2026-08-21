// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { sorobanEventWatcher } from "../services/sorobanEventWatcher.service";

// Minimal browser shim: the watcher targets window timers/dispatch, while the
// suite runs in vitest's node environment.
const installWindowShim = () => {
  (globalThis as any).window = {
    setTimeout: (fn: any, ms?: number) => setTimeout(fn, ms),
    clearTimeout: (id: any) => clearTimeout(id),
    dispatchEvent: vi.fn(() => true),
  };
};

describe("SorobanEventWatcher", () => {
  const rpcUrl = "https://mock.soroban.rpc";
  const contractId = "C123456789";

  beforeEach(() => {
    vi.useFakeTimers();
    global.fetch = vi.fn();
    installWindowShim();
    const mockFetch = vi.fn();
    globalThis.fetch = mockFetch;
    global.fetch = mockFetch;
    if (typeof window !== "undefined") {
      (window as any).fetch = mockFetch;
      vi.spyOn(window, "dispatchEvent").mockImplementation(() => true);
    }
  });

  afterEach(() => {
    sorobanEventWatcher.stop();
    vi.restoreAllMocks();
    vi.useRealTimers();
    // Reset singleton state between tests.
    // @ts-ignore
    sorobanEventWatcher.listeners = {};
    // @ts-ignore
    sorobanEventWatcher.lastCursor = undefined;
    delete (globalThis as any).window;
  });

  it("should not fetch events if not started", async () => {
    // @ts-ignore
    await sorobanEventWatcher.poll();
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("should fetch latest ledger then events on the initial poll", async () => {
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { events: [] } }),
      });

    sorobanEventWatcher.start(rpcUrl, contractId);
    await vi.runOnlyPendingTimersAsync();

    // Initial poll (ledger + events) plus the scheduled follow-up cycle whose
    // un-mocked ledger probe fails silently and aborts the cycle.
    expect(global.fetch).toHaveBeenCalledTimes(3);
    expect(JSON.parse((global.fetch as any).mock.calls[0][1].body).method).toBe("getLatestLedger");

    const eventsCall = JSON.parse((global.fetch as any).mock.calls[1][1].body);
    expect(eventsCall.method).toBe("getEvents");
    expect(eventsCall.params.startLedger).toBe(1000);
  it("should initialize and fetch latest ledger on first poll", async () => {
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: { sequence: 1000 }
        })
      })
      .mockResolvedValue({
        ok: true,
        json: async () => ({
          result: { events: [] }
        })
      });

    sorobanEventWatcher.start(rpcUrl, contractId);
    
    await vi.advanceTimersByTimeAsync(0);

    expect(global.fetch).toHaveBeenCalled();
    const fetchCall1 = (global.fetch as any).mock.calls[0];
    expect(fetchCall1[0]).toBe(rpcUrl);
    expect(JSON.parse(fetchCall1[1].body).method).toBe("getLatestLedger");

    const fetchCall2 = (global.fetch as any).mock.calls[1];
    expect(JSON.parse(fetchCall2[1].body).method).toBe("getEvents");
  });

  it("should fetch events and dispatch to listeners when events are present", async () => {
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { events: [] } }),
      });

    sorobanEventWatcher.start(rpcUrl, contractId);
    await vi.runOnlyPendingTimersAsync();

        json: async () => ({ result: { sequence: 1000 } })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: {
            events: [
              {
                type: "contract",
                pagingToken: "1001-1",
                topic: ["VaultCreated_XDR"],
                value: { some: "data" }
              }
            ]
          }
        })
      });

    const mockCallback = vi.fn();
    sorobanEventWatcher.on("SorobanEvent", mockCallback);

    // Next cycle: ledger lookup followed by the getEvents call carrying one event.
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          result: {
            events: [
              {
                type: "contract",
                pagingToken: "1001-1",
                topic: ["VaultCreated_XDR"],
                value: { some: "data" },
              },
            ],
          },
        }),
      });

    await vi.advanceTimersByTimeAsync(5000);

    // 2 initial + 1 silent probe + ledger + events for the advanced cycle.
    expect(global.fetch).toHaveBeenCalledTimes(5);
    const secondEventsCall = JSON.parse((global.fetch as any).mock.calls[4][1].body);
    expect(secondEventsCall.method).toBe("getEvents");
    expect(secondEventsCall.params.startLedger).toBe(1000);

    expect(mockCallback).toHaveBeenCalledTimes(1);
    expect(mockVaultCallback).toHaveBeenCalledTimes(1);
    // Each event fans out to SorobanEvent, VaultCreated and DocumentAdded topics.
    expect(window.dispatchEvent).toHaveBeenCalledTimes(3);
    sorobanEventWatcher.start(rpcUrl, contractId);
    await vi.advanceTimersByTimeAsync(5000);

    expect(mockCallback).toHaveBeenCalled();

    sorobanEventWatcher.off("SorobanEvent", mockCallback);
  });

  it("should handle RPC errors gracefully", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // getLatestLedger failure is swallowed and yields ledger 0 -> silent abort.
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      statusText: "Internal Server Error",
    });

    sorobanEventWatcher.start(rpcUrl, contractId);
    await vi.runOnlyPendingTimersAsync();

    expect(consoleSpy).not.toHaveBeenCalled();
    // Initial failed ledger + the scheduled cycle's silent probe.
    expect(global.fetch).toHaveBeenCalledTimes(2);

    // Next cycle: ledger succeeds but getEvents fails -> poll() logs the error.
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } }),
      })
      .mockResolvedValueOnce({
        ok: false,
        statusText: "Bad Gateway",
      });

    await vi.advanceTimersByTimeAsync(5000);

    await vi.advanceTimersByTimeAsync(5000);
    
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ result: { sequence: 1000 } })
      })
      .mockResolvedValueOnce({
        ok: false,
        statusText: "Bad Gateway"
      });

    // @ts-ignore
    sorobanEventWatcher.lastCursor = undefined;
    
    // @ts-ignore
    await sorobanEventWatcher.poll();

    expect(consoleSpy).toHaveBeenCalledWith(
      "SorobanEventWatcher polling error:",
      expect.any(Error)
    );
  });
});
