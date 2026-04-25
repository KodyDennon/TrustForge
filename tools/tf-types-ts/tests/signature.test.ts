import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  blake3HashRef,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  fromHex,
  sha256HashRef,
  toHex,
} from "../src/core/crypto";

type Ed25519Vector = {
  name: string;
  private_key: string;
  public_key?: string;
  message: string;
  signature?: string;
};
type HashVector = { name: string; input_hex: string; output: string };

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "signature-vectors.yaml"), "utf8")) as {
  ed25519: Ed25519Vector[];
  sha256: HashVector[];
  blake3: HashVector[];
};

describe("ed25519 parity vectors", () => {
  for (const v of VECTORS.ed25519) {
    test(`${v.name} public-key derivation`, async () => {
      if (!v.public_key) return;
      const derived = await ed25519PublicKey(fromHex(v.private_key));
      expect(toHex(derived)).toBe(v.public_key);
    });

    test(`${v.name} signature is deterministic`, async () => {
      const sig = await ed25519Sign(fromHex(v.message), fromHex(v.private_key));
      if (v.signature) {
        expect(toHex(sig)).toBe(v.signature);
      }
      const pk = v.public_key ? fromHex(v.public_key) : await ed25519PublicKey(fromHex(v.private_key));
      expect(await ed25519Verify(pk, fromHex(v.message), sig)).toBe(true);
    });
  }

  test("verify rejects a tampered message", async () => {
    const v = VECTORS.ed25519[1]!;
    const pk = await ed25519PublicKey(fromHex(v.private_key));
    const sig = await ed25519Sign(fromHex(v.message), fromHex(v.private_key));
    const tampered = new Uint8Array([0xff]);
    expect(await ed25519Verify(pk, tampered, sig)).toBe(false);
  });
});

describe("sha256 parity vectors", () => {
  for (const v of VECTORS.sha256) {
    test(v.name, () => {
      expect(sha256HashRef(fromHex(v.input_hex))).toBe(v.output);
    });
  }
});

describe("blake3 parity vectors", () => {
  for (const v of VECTORS.blake3) {
    test(v.name, () => {
      expect(blake3HashRef(fromHex(v.input_hex))).toBe(v.output);
    });
  }
});
