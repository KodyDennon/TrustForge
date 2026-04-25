import { describe, expect, test } from "bun:test";
import { generateDocs } from "../src/codegen/docs";

describe("docs codegen", () => {
  test("agent-contract page has title and fields table", async () => {
    const out = await generateDocs();
    expect(out["agent-contract.md"]).toBeDefined();
    expect(out["agent-contract.md"]!).toContain("# TrustForge Agent Contract");
    expect(out["agent-contract.md"]!).toContain("| Field | Type | Required | Description |");
    expect(out["agent-contract.md"]!).toContain("`project`");
  });

  test("index lists every schema", async () => {
    const out = await generateDocs();
    expect(out["index.md"]).toBeDefined();
    expect(out["index.md"]!).toContain("[agent-contract]");
    expect(out["index.md"]!).toContain("[proof-bundle]");
    expect(out["index.md"]!).toContain("[_common]");
  });
});
