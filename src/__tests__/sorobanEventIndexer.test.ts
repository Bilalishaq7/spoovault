// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseSorobanEvent, SorobanEventIndexer } from "../services/sorobanEventIndexer.service";

describe("SorobanEventIndexer", () => {
  afterEach(() => vi.restoreAllMocks());

  it("decodes supported topics and rejects unrelated events", () => {
    expect(parseSorobanEvent({ id: "1", topic: ["VaultCreated"], ledger: 4 }, "contract")?.topic).toBe("VaultCreated");
    expect(parseSorobanEvent({ id: "2", topic: ["SomethingElse"] }, "contract")).toBeNull();
  });

  it("distributes parsed events to subscribers", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor", topic: ["GuardianAdded"] }] } }) }));
    const indexer = new SorobanEventIndexer();
    const listener = vi.fn();
    indexer.subscribe(listener);
    indexer.start("https://rpc.example", "contract");
    await vi.waitFor(() => expect(listener).toHaveBeenCalledTimes(1));
    expect(listener.mock.calls[0][0].topic).toBe("GuardianAdded");
    indexer.stop();
  });

  it("uses exponential backoff after an RPC failure", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
    const indexer = new SorobanEventIndexer();
    indexer.start("https://rpc.example", "contract");
    await vi.runOnlyPendingTimersAsync();
    expect(fetch).toHaveBeenCalled();
    indexer.stop();
    vi.useRealTimers();
  });
});
