import { describe, expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
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
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const v = ajv.compile(bundled);
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
