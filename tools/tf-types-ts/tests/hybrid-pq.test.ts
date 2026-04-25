/**
 * Hybrid post-quantum signing tests. Verifies:
 * - ml-dsa-44/65/87 round-trip via @noble/post-quantum
 * - hybridSign produces an envelope where BOTH ed25519 AND ml-dsa
 *   signatures are required for hybridVerify to return true
 * - Initiator advertises supported suites, including the hybrid one
 */

import { describe, expect, test } from "bun:test";
import {
  hybridGenerate,
  hybridSign,
  hybridVerify,
  KNOWN_SESSION_SUITES,
  Initiator,
  mldsaGenerate,
  mldsaSign,
  mldsaVerify,
  ed25519Generate,
  SESSION_SUITE_HYBRID_ED25519_MLDSA65,
} from "../src/index";

describe("ML-DSA suites", () => {
  for (const suite of ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] as const) {
    test(`${suite} round-trip sign / verify`, () => {
      const k = mldsaGenerate(suite);
      const msg = new TextEncoder().encode("hello quantum world");
      const sig = mldsaSign(suite, k.privateKey, msg);
      expect(mldsaVerify(suite, k.publicKey, msg, sig)).toBe(true);
      // Tampered message rejected
      const tampered = new TextEncoder().encode("hello quantum world!");
      expect(mldsaVerify(suite, k.publicKey, tampered, sig)).toBe(false);
    });
  }
});

describe("Hybrid (Ed25519 + ML-DSA) signatures", () => {
  test("hybridVerify accepts when both signatures are valid", async () => {
    const pair = await hybridGenerate("ml-dsa-65");
    const msg = new TextEncoder().encode("payload to authenticate");
    const sig = await hybridSign(pair, msg);
    const ok = await hybridVerify(
      pair.classical.publicKey,
      pair.pq.publicKey,
      pair.pqSuite,
      msg,
      sig,
    );
    expect(ok).toBe(true);
    expect(sig.algorithm).toBe("ed25519");
    expect(sig.alt_algorithm).toBe("ml-dsa-65");
    expect(sig.signature.length).toBe(64);
    expect(sig.alt_signature.length).toBeGreaterThan(2000);
  });

  test("hybridVerify rejects when the classical signature is forged", async () => {
    const pair = await hybridGenerate("ml-dsa-65");
    const msg = new TextEncoder().encode("payload");
    const sig = await hybridSign(pair, msg);
    // Replace classical sig with a different (valid-looking) one from a fresh key
    const other = await ed25519Generate();
    sig.signature = await (await import("@noble/ed25519")).signAsync(msg, other.privateKey);
    const ok = await hybridVerify(
      pair.classical.publicKey,
      pair.pq.publicKey,
      pair.pqSuite,
      msg,
      sig,
    );
    expect(ok).toBe(false);
  });

  test("hybridVerify rejects when the PQ signature is forged", async () => {
    const pair = await hybridGenerate("ml-dsa-65");
    const msg = new TextEncoder().encode("payload");
    const sig = await hybridSign(pair, msg);
    // Replace alt sig with a sig from a different ML-DSA key
    const otherPq = mldsaGenerate("ml-dsa-65");
    sig.alt_signature = mldsaSign("ml-dsa-65", otherPq.privateKey, msg);
    const ok = await hybridVerify(
      pair.classical.publicKey,
      pair.pq.publicKey,
      pair.pqSuite,
      msg,
      sig,
    );
    expect(ok).toBe(false);
  });

  test("hybridVerify rejects when the PQ suite is mismatched", async () => {
    const pair = await hybridGenerate("ml-dsa-65");
    const msg = new TextEncoder().encode("payload");
    const sig = await hybridSign(pair, msg);
    // Lying about the alt_algorithm
    sig.alt_algorithm = "ml-dsa-87" as typeof sig.alt_algorithm;
    const ok = await hybridVerify(
      pair.classical.publicKey,
      pair.pq.publicKey,
      pair.pqSuite,
      msg,
      sig,
    );
    expect(ok).toBe(false);
  });
});

describe("Session suite negotiation", () => {
  test("KNOWN_SESSION_SUITES includes both classical and hybrid", () => {
    expect(KNOWN_SESSION_SUITES).toContain(
      "x25519-hkdf-sha256-chacha20poly1305-ed25519",
    );
    expect(KNOWN_SESSION_SUITES).toContain(SESSION_SUITE_HYBRID_ED25519_MLDSA65);
  });

  test("Initiator.start defaults to the classical suite but advertises both", async () => {
    const id = await ed25519Generate();
    const initiator = new Initiator({
      selfActor: "tf:actor:agent:example.com/i",
      identityPriv: id.privateKey,
      identityPub: id.publicKey,
    });
    const hello = initiator.start();
    expect(hello.suite).toBe("x25519-hkdf-sha256-chacha20poly1305-ed25519");
    expect(hello.supported_suites).toContain(SESSION_SUITE_HYBRID_ED25519_MLDSA65);
  });

  test("Initiator can be configured to prefer the hybrid suite", async () => {
    const id = await ed25519Generate();
    const initiator = new Initiator({
      selfActor: "tf:actor:agent:example.com/i",
      identityPriv: id.privateKey,
      identityPub: id.publicKey,
      preferredSuite: SESSION_SUITE_HYBRID_ED25519_MLDSA65,
    });
    const hello = initiator.start();
    expect(hello.suite).toBe(SESSION_SUITE_HYBRID_ED25519_MLDSA65);
  });
});
