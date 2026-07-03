import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "../src/core/yaml.js";
import {
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
  fromHex,
  hkdfSha256,
  toHex,
  x25519DiffieHellman,
  x25519Generate,
} from "../src/core/crypto";

type X25519Vec = { name: string; private_key: string; peer_public: string; shared: string };
type HkdfVec = { name: string; ikm: string; salt: string; info: string; length: number; output: string };
type AeadVec = {
  name: string;
  key: string;
  nonce: string;
  aad: string;
  plaintext: string;
  ciphertext_with_tag: string;
};

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "session-vectors.yaml"), "utf8")) as {
  x25519: X25519Vec[];
  hkdf_sha256: HkdfVec[];
  chacha20poly1305: AeadVec[];
};

describe("X25519 vectors", () => {
  for (const v of VECTORS.x25519) {
    test(v.name, () => {
      const shared = x25519DiffieHellman(fromHex(v.private_key), fromHex(v.peer_public));
      expect(toHex(shared)).toBe(v.shared);
    });
  }

  test("DH is symmetric", () => {
    const a = x25519Generate();
    const b = x25519Generate();
    const ab = x25519DiffieHellman(a.privateKey, b.publicKey);
    const ba = x25519DiffieHellman(b.privateKey, a.publicKey);
    expect(toHex(ab)).toBe(toHex(ba));
  });
});

describe("HKDF-SHA256 vectors", () => {
  for (const v of VECTORS.hkdf_sha256) {
    test(v.name, () => {
      const out = hkdfSha256(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.length);
      expect(toHex(out)).toBe(v.output);
    });
  }
});

describe("ChaCha20-Poly1305 vectors", () => {
  for (const v of VECTORS.chacha20poly1305) {
    test(`${v.name} encrypt`, () => {
      const ct = chacha20poly1305Encrypt(fromHex(v.key), fromHex(v.nonce), fromHex(v.aad), fromHex(v.plaintext));
      expect(toHex(ct)).toBe(v.ciphertext_with_tag);
    });
    test(`${v.name} decrypt`, () => {
      const pt = chacha20poly1305Decrypt(
        fromHex(v.key),
        fromHex(v.nonce),
        fromHex(v.aad),
        fromHex(v.ciphertext_with_tag),
      );
      expect(toHex(pt)).toBe(v.plaintext);
    });
  }

  test("decrypt rejects tampered ciphertext", () => {
    const v = VECTORS.chacha20poly1305[0]!;
    const ct = fromHex(v.ciphertext_with_tag);
    ct[0]! ^= 0xff;
    expect(() =>
      chacha20poly1305Decrypt(fromHex(v.key), fromHex(v.nonce), fromHex(v.aad), ct),
    ).toThrow();
  });
});
