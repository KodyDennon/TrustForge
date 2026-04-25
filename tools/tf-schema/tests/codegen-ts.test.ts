import { describe, expect, test } from "bun:test";
import { generateTs } from "../src/codegen/ts";

describe("TS codegen", () => {
  test("emits RiskClass as a string-literal union in _common.ts", async () => {
    const out = await generateTs();
    expect(out["_common.ts"]).toBeDefined();
    expect(out["_common.ts"]!).toContain('"R0"');
    expect(out["_common.ts"]!).toContain('"R5"');
    expect(out["_common.ts"]!).toContain("export type RiskClass");
  });

  test("agent-contract imports RiskClass from _common", async () => {
    const out = await generateTs();
    expect(out["agent-contract.ts"]).toBeDefined();
    expect(out["agent-contract.ts"]!).toContain('import type');
    expect(out["agent-contract.ts"]!).toContain('from "./_common.js"');
    expect(out["agent-contract.ts"]!).toContain("export interface AgentContract");
    expect(out["agent-contract.ts"]!).toContain("project: string");
  });

  test("Constraint emits a tagged union", async () => {
    const out = await generateTs();
    expect(out["_common.ts"]!).toContain("export type Constraint");
    expect(out["_common.ts"]!).toContain('kind: "time_window"');
    expect(out["_common.ts"]!).toContain('kind: "rate"');
  });

  test("proof-bundle references ProofEvent as a whole-schema type", async () => {
    const out = await generateTs();
    expect(out["proof-bundle.ts"]).toBeDefined();
    expect(out["proof-bundle.ts"]!).toContain("ProofEvent");
    expect(out["proof-bundle.ts"]!).toContain('from "./proof-event.js"');
  });

  test("barrel index re-exports every schema", async () => {
    const out = await generateTs();
    expect(out["index.ts"]).toBeDefined();
    expect(out["index.ts"]!).toContain('export * from "./_common.js"');
    expect(out["index.ts"]!).toContain('export * from "./agent-contract.js"');
    expect(out["index.ts"]!).toContain('export * from "./proof-bundle.js"');
  });
});
