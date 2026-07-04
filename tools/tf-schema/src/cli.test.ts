import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { SchemaRegistry } from "./validator";
import { parseYaml as parseYAML } from "@trustforge-protocol/types";

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const SCHEMA_PATH = join(REPO_ROOT, "schemas", "agent-contract.schema.json");
const COMMON_PATH = join(REPO_ROOT, "schemas", "_common.schema.json");
const EXAMPLE_PATH = join(REPO_ROOT, "examples", "agent-contracts", "minimal.yaml");

function makeValidator() {
  const registry = new SchemaRegistry();
  const common = JSON.parse(readFileSync(COMMON_PATH, "utf8"));
  registry.addSchema(common, "_common.schema.json");
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
  return registry.compile(schema);
}

const validate = makeValidator();
const baseline = parseYAML(readFileSync(EXAMPLE_PATH, "utf8")) as Record<string, unknown>;

describe("agent-contract schema", () => {
  test("minimal example validates", () => {
    expect(validate(baseline)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  test("rejects missing required field", () => {
    const { project: _drop, ...broken } = baseline;
    expect(validate(broken)).toBe(false);
    expect(validate.errors?.some((e) => e.message?.includes("'project'"))).toBe(true);
  });

  test("rejects unknown top-level key", () => {
    const broken = { ...baseline, unexpected: true };
    expect(validate(broken)).toBe(false);
  });

  test("rejects invalid risk class", () => {
    const broken = structuredClone(baseline) as any;
    broken.actions[0].risk = "R9";
    expect(validate(broken)).toBe(false);
  });

  test("rejects malformed action name", () => {
    const broken = structuredClone(baseline) as any;
    broken.actions[0].name = "FileWrite";
    expect(validate(broken)).toBe(false);
  });

  test("rejects forbidden entry without action", () => {
    const broken = structuredClone(baseline) as any;
    broken.forbidden = [{ reason: "nope" }];
    expect(validate(broken)).toBe(false);
  });

  test("rejects spec_version that doesn't match TF-NNNN pattern", () => {
    const broken = { ...baseline, spec_version: "v1" };
    expect(validate(broken)).toBe(false);
  });

  test("agent-contract uses v0 $id", () => {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as { $id: string };
    expect(schema.$id).toBe("https://trustforge.io/schemas/v0/agent-contract.schema.json");
  });

  test("agent-contract $refs _common for RiskClass", () => {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
    const text = JSON.stringify(schema);
    expect(text).toContain("_common.schema.json#/$defs/RiskClass");
  });
});
