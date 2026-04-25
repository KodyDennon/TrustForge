import { describe, expect, test } from "bun:test";
import { fuzzAll, fuzzSchema } from "../src/fuzz";

describe("fuzz", () => {
  test("agent-contract fuzz terminates without panics", async () => {
    const r = await fuzzSchema("agent-contract", { iterations: 300 });
    expect(r.panics).toEqual([]);
    expect(r.accepted + r.rejected).toBe(r.iterations);
  });

  test("fuzz across every schema produces no panics", async () => {
    const results = await fuzzAll(50);
    const allPanics = results.flatMap((r) => r.panics);
    expect(allPanics).toEqual([]);
    for (const r of results) {
      expect(r.accepted + r.rejected).toBe(r.iterations);
    }
  });
});
