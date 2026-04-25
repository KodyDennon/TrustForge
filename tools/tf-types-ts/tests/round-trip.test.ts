import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { parse as parseYAML } from "yaml";
import { canonicalize } from "../src/core/canonical";

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "schemas", "fixtures");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".yaml") && !p.endsWith(".expected-error.yaml")) out.push(p);
  }
  return out;
}

describe("round-trip", () => {
  for (const f of walk(FIXTURES).filter((p) => p.includes("/valid/") || p.includes("/composite/"))) {
    test(`canonicalize is idempotent for ${relative(REPO_ROOT, f)}`, () => {
      const doc = parseYAML(readFileSync(f, "utf8"));
      const a = canonicalize(doc);
      const b = canonicalize(JSON.parse(a));
      expect(a).toBe(b);
    });
  }
});
