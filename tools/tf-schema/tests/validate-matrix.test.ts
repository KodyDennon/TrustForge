import { describe, expect, test } from "bun:test";
import { runValidateAll } from "../src/validate";

describe("validate-all with fixtures", () => {
  test("agent-contract fixtures: all valid pass, all invalid fail with expected errors", async () => {
    const result = await runValidateAll({ schema: "agent-contract" });
    expect(result.summary.mismatches).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.summary.validPassed).toBeGreaterThan(0);
    expect(result.summary.invalidMatched).toBeGreaterThan(0);
  });
});
