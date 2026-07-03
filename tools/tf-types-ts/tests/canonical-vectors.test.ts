import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "../src/core/yaml.js";
import { canonicalize } from "../src/core/canonical";

type Vector = { name: string; input: unknown; output: string };

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "canonical-vectors.yaml"), "utf8")) as { vectors: Vector[] };

describe("canonical-vectors", () => {
  for (const v of VECTORS.vectors) {
    test(`TS matches expected output for ${v.name}`, () => {
      expect(canonicalize(v.input)).toBe(v.output);
    });
  }
});
