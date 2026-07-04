import { describe, expect, test } from "bun:test";
import { SchemaRegistry } from "../src/validator";
import { bundleSchema } from "../src/bundle";

describe("bundle", () => {
  test("inlines _common $refs", async () => {
    const bundled = await bundleSchema("agent-contract");
    const text = JSON.stringify(bundled);
    expect(text).not.toContain("_common.schema.json");
    expect(text).toContain('"R0"');
  });

  test("bundled agent-contract is self-contained and AJV-compilable", async () => {
    const bundled = await bundleSchema("agent-contract");
    const v = new SchemaRegistry().compile(bundled as object);
    const valid = {
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "test",
    };
    expect(v(valid)).toBe(true);
  });

  test("bundling proof-bundle inlines proof-event schema", async () => {
    const bundled = await bundleSchema("proof-bundle");
    const text = JSON.stringify(bundled);
    expect(text).not.toContain("proof-event.schema.json");
    expect(text).not.toContain("_common.schema.json");
  });
});
