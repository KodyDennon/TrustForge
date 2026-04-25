import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
import type { ProofEvent } from "../src/generated/proof-event";
import { chainHash, eventHash, merkleRoot, verifyChain, ChainError } from "../src/core/chain";

type Case = {
  name: string;
  events: (ProofEvent & { parent_hash?: string })[];
  expect: { chain_valid: boolean };
};

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "chain-vectors.yaml"), "utf8")) as { cases: Case[] };

function realizeChain(events: Case["events"]): ProofEvent[] {
  const out: ProofEvent[] = [];
  for (let i = 0; i < events.length; i++) {
    const copy = { ...events[i]! };
    if (copy.parent_hash === "__derive_from_prev__") {
      copy.parent_hash = eventHash(out[i - 1]!);
    }
    out.push(copy as ProofEvent);
  }
  return out;
}

describe("chain-vectors", () => {
  for (const c of VECTORS.cases) {
    test(`${c.name} chain verification`, () => {
      const events = realizeChain(c.events);
      if (c.expect.chain_valid) {
        expect(() => verifyChain(events)).not.toThrow();
      } else {
        expect(() => verifyChain(events)).toThrow(ChainError);
      }
    });

    test(`${c.name} merkle root is stable`, () => {
      const events = realizeChain(c.events);
      const root = merkleRoot(events);
      expect(root).toMatch(/^sha256:[0-9a-f]{64}$/);
      // Recomputing must produce the same bytes.
      expect(merkleRoot(events)).toBe(root);
    });

    test(`${c.name} chain hash is stable`, () => {
      const events = realizeChain(c.events);
      const hash = chainHash(events);
      expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(chainHash(events)).toBe(hash);
    });
  }

  test("single-event merkle equals event hash", () => {
    const events = realizeChain(VECTORS.cases[0]!.events);
    expect(merkleRoot(events)).toBe(eventHash(events[0]!));
  });

  test("empty chain merkle is the zero-sentinel", () => {
    expect(merkleRoot([])).toBe("sha256:" + "00".repeat(32));
  });
});
