import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "../src/core/yaml.js";
import type { ProofBundle } from "../src/generated/proof-bundle";
import type { ProofEvent } from "../src/generated/proof-event";
import { fromHex, toHex } from "../src/core/crypto";
import {
  FormatError,
  TFLOG_MAGIC,
  TFPROOF_MAGIC,
  readTflog,
  readTfproof,
  writeTflog,
  writeTfproof,
} from "../src/core/format";

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "framing-vectors.yaml"), "utf8")) as {
  tflog: { name: string; events: ProofEvent[]; expected_hex?: string }[];
  tfproof: { name: string; bundle: ProofBundle; signature_hex: string; expected_hex?: string }[];
};

describe(".tflog framing", () => {
  for (const c of VECTORS.tflog) {
    test(`${c.name} round-trips`, () => {
      const framed = writeTflog(c.events);
      expect(framed.slice(0, 8)).toEqual(TFLOG_MAGIC);
      const parsed = readTflog(framed);
      expect(parsed.length).toBe(c.events.length);
      // Re-serialize: output must be byte-identical.
      const reframed = writeTflog(parsed);
      expect(toHex(reframed)).toBe(toHex(framed));
      if (c.expected_hex) expect(toHex(framed)).toBe(c.expected_hex);
    });
  }

  test("bad magic rejected", () => {
    const bad = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(() => readTflog(bad)).toThrow(FormatError);
  });

  test("truncated frame rejected", () => {
    const events = VECTORS.tflog[0]!.events;
    const framed = writeTflog(events);
    const chopped = framed.slice(0, framed.length - 1);
    expect(() => readTflog(chopped)).toThrow(FormatError);
  });
});

describe(".tfproof framing", () => {
  for (const c of VECTORS.tfproof) {
    test(`${c.name} round-trips`, () => {
      const sig = fromHex(c.signature_hex);
      const framed = writeTfproof(c.bundle, sig);
      expect(framed.slice(0, 8)).toEqual(TFPROOF_MAGIC);
      const parsed = readTfproof(framed);
      expect(toHex(parsed.signature)).toBe(c.signature_hex);
      // Re-serialize with the parsed body + sig: byte-identical output.
      const reframed = writeTfproof(parsed.bundle, parsed.signature);
      expect(toHex(reframed)).toBe(toHex(framed));
      if (c.expected_hex) expect(toHex(framed)).toBe(c.expected_hex);
    });
  }

  test("bad magic rejected", () => {
    const bad = new Uint8Array(16);
    expect(() => readTfproof(bad)).toThrow(FormatError);
  });
});
