import { describe, expect, test } from "bun:test";
import { lintSchemas } from "../src/lint";

describe("lint", () => {
  test("passes on current schemas", async () => {
    const result = await lintSchemas();
    if (result.issues.length > 0) {
      for (const i of result.issues) console.error(`${i.file}${i.path} [${i.rule}] ${i.message}`);
    }
    expect(result.issues).toEqual([]);
  });
});
