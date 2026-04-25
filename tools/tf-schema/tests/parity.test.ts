import { describe, expect, test } from "bun:test";
import { generateParity, runParityTs } from "../src/parity";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../src/loader";
import { serializeParity } from "../src/parity";

describe("parity", () => {
  test("generateParity enumerates every fixture with an expectation", async () => {
    const parity = await generateParity();
    expect(parity.vectors.length).toBeGreaterThan(30);
    const validCount = parity.vectors.filter((v) => v.expect === "valid").length;
    const invalidCount = parity.vectors.filter((v) => v.expect === "invalid").length;
    expect(validCount).toBeGreaterThan(0);
    expect(invalidCount).toBeGreaterThan(0);
  });

  test("TS side agrees with every parity vector", async () => {
    const parity = await generateParity();
    const path = join(REPO_ROOT, "conformance", "parity.yaml");
    writeFileSync(path, serializeParity(parity));
    const result = await runParityTs(path);
    if (!result.ok) console.error(JSON.stringify(result.mismatches, null, 2));
    expect(result.ok).toBe(true);
  });
});
