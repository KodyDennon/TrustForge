/**
 * Security negative tests — explicit coverage for the failure modes
 * that audit-grade reviews always check for.
 */

import { describe, expect, test } from "bun:test";
import {
  AeadError,
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
  ed25519Generate,
  ed25519Sign,
  ed25519Verify,
} from "../src/index";
import { signPacket, verifyPacket } from "../src/core/packet";
import {
  migrateSession,
  verifySessionMigration,
} from "../src/core/session-migration";
import type { TransportBinding } from "../src/generated/transport-binding";

const emptyBinding = (kind: TransportBinding["kind"] = "websocket"): TransportBinding => ({
  binding_version: "1",
  kind,
});

describe("AEAD negatives — ChaCha20-Poly1305", () => {
  test("tampered ciphertext fails authentication", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const ct = chacha20poly1305Encrypt(key, nonce, new Uint8Array(0), new TextEncoder().encode("hi"));
    ct[0]! ^= 0xff;
    expect(() => chacha20poly1305Decrypt(key, nonce, new Uint8Array(0), ct)).toThrow(AeadError);
  });

  test("wrong key fails authentication", () => {
    const k1 = new Uint8Array(32);
    crypto.getRandomValues(k1);
    const k2 = new Uint8Array(32);
    crypto.getRandomValues(k2);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const ct = chacha20poly1305Encrypt(k1, nonce, new Uint8Array(0), new TextEncoder().encode("hi"));
    expect(() => chacha20poly1305Decrypt(k2, nonce, new Uint8Array(0), ct)).toThrow(AeadError);
  });

  test("wrong nonce fails authentication", () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const n1 = new Uint8Array(12);
    crypto.getRandomValues(n1);
    const n2 = new Uint8Array(12);
    crypto.getRandomValues(n2);
    const ct = chacha20poly1305Encrypt(key, n1, new Uint8Array(0), new TextEncoder().encode("hi"));
    expect(() => chacha20poly1305Decrypt(key, n2, new Uint8Array(0), ct)).toThrow(AeadError);
  });

  test("AAD mismatch fails authentication", () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const ct = chacha20poly1305Encrypt(
      key,
      nonce,
      new TextEncoder().encode("aad-A"),
      new TextEncoder().encode("hi"),
    );
    expect(() =>
      chacha20poly1305Decrypt(key, nonce, new TextEncoder().encode("aad-B"), ct),
    ).toThrow(AeadError);
  });

  test("invalid key length raises AeadError synchronously", () => {
    const shortKey = new Uint8Array(16);
    const nonce = new Uint8Array(12);
    expect(() =>
      chacha20poly1305Encrypt(shortKey, nonce, new Uint8Array(0), new Uint8Array(0)),
    ).toThrow(AeadError);
  });

  test("invalid nonce length raises AeadError synchronously", () => {
    const key = new Uint8Array(32);
    const shortNonce = new Uint8Array(8);
    expect(() =>
      chacha20poly1305Encrypt(key, shortNonce, new Uint8Array(0), new Uint8Array(0)),
    ).toThrow(AeadError);
  });
});

describe("ed25519 malleability + key-length checks", () => {
  test("rejects 0-length signature without throwing", async () => {
    const pair = await ed25519Generate();
    const ok = await ed25519Verify(pair.publicKey, new TextEncoder().encode("x"), new Uint8Array(0));
    expect(ok).toBe(false);
  });

  test("rejects 65-byte signature (over-long)", async () => {
    const pair = await ed25519Generate();
    const sig = await ed25519Sign(new TextEncoder().encode("x"), pair.privateKey);
    const overLong = new Uint8Array(65);
    overLong.set(sig);
    overLong[64] = 0xff;
    const ok = await ed25519Verify(pair.publicKey, new TextEncoder().encode("x"), overLong);
    expect(ok).toBe(false);
  });

  test("flipping last byte of signature flips verification", async () => {
    const pair = await ed25519Generate();
    const msg = new TextEncoder().encode("verify-me");
    const sig = await ed25519Sign(msg, pair.privateKey);
    expect(await ed25519Verify(pair.publicKey, msg, sig)).toBe(true);
    const tampered = new Uint8Array(sig);
    tampered[63]! ^= 0x01;
    expect(await ed25519Verify(pair.publicKey, msg, tampered)).toBe(false);
  });

  test("verifying under wrong key returns false (not throws)", async () => {
    const a = await ed25519Generate();
    const b = await ed25519Generate();
    const msg = new TextEncoder().encode("x");
    const sig = await ed25519Sign(msg, a.privateKey);
    expect(await ed25519Verify(b.publicKey, msg, sig)).toBe(false);
  });
});

describe("Session replay — explicit generation enforcement", () => {
  test("a migration replayed at the same generation is rejected", async () => {
    const pair = await ed25519Generate();
    const m = await migrateSession({
      sessionId: "s",
      generation: 1,
      fromBinding: emptyBinding(),
      toBinding: emptyBinding("quic"),
      signer: "tf:actor:agent:example.com/x",
      privateKey: pair.privateKey,
    });
    const first = await verifySessionMigration({
      migration: m,
      publicKey: pair.publicKey,
      lastGeneration: 0,
    });
    const second = await verifySessionMigration({
      migration: m,
      publicKey: pair.publicKey,
      lastGeneration: 1,
    });
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
  });

  test("a migration whose generation < last seen is rejected", async () => {
    const pair = await ed25519Generate();
    const stale = await migrateSession({
      sessionId: "s",
      generation: 3,
      fromBinding: emptyBinding(),
      toBinding: emptyBinding("websocket"),
      signer: "tf:actor:agent:example.com/x",
      privateKey: pair.privateKey,
    });
    const r = await verifySessionMigration({
      migration: stale,
      publicKey: pair.publicKey,
      lastGeneration: 5,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/generation/);
  });
});

describe("Packet replay + tamper", () => {
  test("packet with flipped signature byte fails verification", async () => {
    const pair = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-tamper",
      source: "tf:actor:agent:example.com/x",
      destination: "tf:actor:service:example.com/d",
      priority: "P3",
      payload: new TextEncoder().encode("hi"),
      privateKey: pair.privateKey,
      signer: "tf:actor:agent:example.com/x",
      createdAt: "2026-04-24T12:00:00Z",
    });
    // Decode → flip first byte → re-encode so we know the signature
    // bytes really changed (changing a base64 char alone can sometimes
    // be a no-op on padding boundaries).
    const sigBytes = new Uint8Array(Buffer.from(p.signature.signature, "base64"));
    sigBytes[0]! ^= 0x01;
    const tamperedSig = Buffer.from(sigBytes).toString("base64");
    const tampered = { ...p, signature: { ...p.signature, signature: tamperedSig } };
    const v = await verifyPacket(tampered, pair.publicKey, "2026-04-24T12:30:00Z");
    expect(v.ok).toBe(false);
  });

  test("packet with mutated payload fails verification", async () => {
    const pair = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-payload",
      source: "tf:actor:agent:example.com/x",
      destination: "tf:actor:service:example.com/d",
      priority: "P3",
      payload: new TextEncoder().encode("original"),
      privateKey: pair.privateKey,
      signer: "tf:actor:agent:example.com/x",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const mutated = {
      ...p,
      payload: Buffer.from(new TextEncoder().encode("malicious")).toString("base64"),
    };
    const v = await verifyPacket(mutated, pair.publicKey, "2026-04-24T12:30:00Z");
    expect(v.ok).toBe(false);
  });
});
