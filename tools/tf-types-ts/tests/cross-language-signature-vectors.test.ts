/**
 * TS half of the cross-language signature parity vectors. The Rust mirror
 * lives at crates/tf-types/tests/cross_language_signature_vectors.rs. Both
 * runtimes:
 *   1. canonicalize the YAML `payload`,
 *   2. sha256 the UTF-8 bytes,
 *   3. ed25519-sign the digest with the listed private key.
 * ed25519 is deterministic (RFC 8032), so both runtimes MUST produce the
 * exact same signature bytes — which means a TS-produced signature
 * verifies under the Rust verifier and vice versa, even without
 * shipping the signature byte-string in the vector file.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
import { sha256 } from "@noble/hashes/sha2";
import { canonicalize, ed25519PublicKey, ed25519Sign, ed25519Verify } from "../src/index";

interface Vector {
  name: string;
  private_key_hex: string;
  public_key_hex: string;
  payload: unknown;
  canonical: string;
}

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const file = readFileSync(join(REPO_ROOT, "conformance", "cross-language-signature-vectors.yaml"), "utf8");
const VECTORS = (parseYAML(file) as { vectors: Vector[] }).vectors;

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("cross-language-signature-vectors", () => {
  for (const v of VECTORS) {
    test(`canonicalize matches the listed canonical bytes — ${v.name}`, () => {
      expect(canonicalize(v.payload)).toBe(v.canonical);
    });

    test(`derived public key from priv matches the listed public_key — ${v.name}`, async () => {
      const priv = fromHex(v.private_key_hex);
      const pubDerived = await ed25519PublicKey(priv);
      const pubExpected = fromHex(v.public_key_hex);
      expect(pubDerived).toEqual(pubExpected);
    });

    test(`sign + verify the canonical bytes round-trip — ${v.name}`, async () => {
      const priv = fromHex(v.private_key_hex);
      const pub = fromHex(v.public_key_hex);
      const digest = sha256(new TextEncoder().encode(v.canonical));
      const sig = await ed25519Sign(digest, priv);
      const ok = await ed25519Verify(pub, digest, sig);
      expect(ok).toBe(true);
    });

    test(`tampered payload digest fails verification — ${v.name}`, async () => {
      const priv = fromHex(v.private_key_hex);
      const pub = fromHex(v.public_key_hex);
      const digest = sha256(new TextEncoder().encode(v.canonical));
      const sig = await ed25519Sign(digest, priv);
      const tamperedDigest = sha256(new TextEncoder().encode(v.canonical + "x"));
      const ok = await ed25519Verify(pub, tamperedDigest, sig);
      expect(ok).toBe(false);
    });
  }
});
