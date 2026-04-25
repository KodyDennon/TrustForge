import { describe, expect, test } from "bun:test";
import {
  ALL_SCENARIOS,
  asShadowDecision,
  runAllScenarios,
  runScenario,
  type GuardDecision,
} from "../src/index";

describe("Simulation harness", () => {
  test("ALL_SCENARIOS exposes 12 distinct names", () => {
    expect(ALL_SCENARIOS.length).toBe(12);
    expect(new Set(ALL_SCENARIOS).size).toBe(12);
  });

  for (const name of ALL_SCENARIOS) {
    test(`scenario ${name} runs and reports ok=true`, async () => {
      const result = await runScenario(name);
      expect(result.name).toBe(name);
      if (!result.ok) {
        // Surface failures inline so a CI rerun shows what tripped.
        console.error(`scenario ${name} failures:`, result.failures);
        console.error(`scenario ${name} observations:`, result.observations);
      }
      expect(result.ok).toBe(true);
      expect(result.observations.length).toBeGreaterThan(0);
    });
  }

  test("runAllScenarios returns one result per scenario", async () => {
    const results = await runAllScenarios();
    expect(results.length).toBe(ALL_SCENARIOS.length);
    expect(results.every((r) => r.ok)).toBe(true);
  });

  test("asShadowDecision softens deny/escalate to log-only", () => {
    const denied: GuardDecision = { kind: "deny", reason: "x", danger_tags: [] };
    expect(asShadowDecision(denied).kind).toBe("log-only");
    const escalated: GuardDecision = {
      kind: "escalate",
      reason: "destructive",
      danger_tags: ["destructive"],
    };
    expect(asShadowDecision(escalated).kind).toBe("log-only");
    const allowed: GuardDecision = { kind: "allow", danger_tags: [] };
    expect(asShadowDecision(allowed).kind).toBe("allow");
  });
});
