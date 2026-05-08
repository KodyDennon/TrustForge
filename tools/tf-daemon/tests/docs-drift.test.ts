import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";

const repoRoot = join(import.meta.dir, "..", "..", "..");
const scanRoots = ["README.md", "ROADMAP.md", "docs", "tools/native"];
const allowedExts = new Set([".md", ".txt", ".c", ".go", ".rs", ".yaml", ".yml", ".sh"]);
const staleClaim = /\b(tf-daemon|reference TrustForge daemon|reference `tf-daemon`|reference daemon)\b.{0,80}\b(not yet shipped|is not shipped|are not yet shipped|planned but not shipped)\b|\bplanned name\b/i;

function collectFiles(path: string): string[] {
  const abs = join(repoRoot, path);
  const stat = statSync(abs);
  if (stat.isFile()) return [abs];
  const out: string[] = [];
  for (const entry of readdirSync(abs)) {
    if (path === "docs" && entry === "superpowers") continue;
    out.push(...collectFiles(join(path, entry)));
  }
  return out;
}

describe("documentation drift checks", () => {
  test("public docs and native comments do not claim the shipped daemon is absent", () => {
    const hits: string[] = [];
    for (const root of scanRoots) {
      for (const file of collectFiles(root)) {
        if (!allowedExts.has(extname(file))) continue;
        const text = readFileSync(file, "utf8");
        const match = staleClaim.exec(text);
        if (match) hits.push(`${relative(repoRoot, file)}: ${match[0]}`);
      }
    }
    expect(hits).toEqual([]);
  });
});
