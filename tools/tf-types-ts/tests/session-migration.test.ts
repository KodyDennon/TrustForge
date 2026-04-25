import { describe, expect, test } from "bun:test";
import {
  ed25519Generate,
  migrationSigningBytes,
  migrateSession,
  Ratchet,
  verifySessionMigration,
  type TransportBinding,
} from "../src/index";

const FROM: TransportBinding = {
  binding_version: "1",
  kind: "websocket",
  endpoint: "wss://daemon.example.com/tf",
  established_at: "2026-04-24T12:00:00Z",
};
const TO: TransportBinding = {
  binding_version: "1",
  kind: "quic",
  endpoint: "quic://daemon.example.com:7443",
  established_at: "2026-04-24T12:05:00Z",
};

describe("Session migration", () => {
  test("signed migration round-trips and verifies", async () => {
    const pair = await ed25519Generate();
    const m = await migrateSession({
      sessionId: "AAECAwQFBgcICQoLDA0ODw==",
      generation: 1,
      fromBinding: FROM,
      toBinding: TO,
      rotatedKeys: true,
      reason: "client roamed; upgrade to QUIC",
      signer: "tf:actor:agent:example.com/code-helper",
      privateKey: pair.privateKey,
    });
    expect(m.session_id).toBe("AAECAwQFBgcICQoLDA0ODw==");
    expect(m.generation).toBe(1);
    expect(m.rotated_keys).toBe(true);
    const v = await verifySessionMigration({
      migration: m,
      publicKey: pair.publicKey,
      expectedSessionId: m.session_id,
    });
    expect(v.ok).toBe(true);
  });

  test("verify rejects tampered to_binding", async () => {
    const pair = await ed25519Generate();
    const m = await migrateSession({
      sessionId: "AAECAwQFBgcICQoLDA0ODw==",
      generation: 1,
      fromBinding: FROM,
      toBinding: TO,
      signer: "tf:actor:agent:example.com/code-helper",
      privateKey: pair.privateKey,
    });
    m.to_binding = { ...TO, endpoint: "quic://attacker.example.com" };
    const v = await verifySessionMigration({ migration: m, publicKey: pair.publicKey });
    expect(v.ok).toBe(false);
  });

  test("verify rejects replay (generation must be strictly greater)", async () => {
    const pair = await ed25519Generate();
    const m = await migrateSession({
      sessionId: "AAECAwQFBgcICQoLDA0ODw==",
      generation: 1,
      fromBinding: FROM,
      toBinding: TO,
      signer: "tf:actor:agent:example.com/code-helper",
      privateKey: pair.privateKey,
    });
    const v = await verifySessionMigration({
      migration: m,
      publicKey: pair.publicKey,
      lastGeneration: 1,
    });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain("replay");
  });

  test("verify rejects mismatched session_id", async () => {
    const pair = await ed25519Generate();
    const m = await migrateSession({
      sessionId: "AAECAwQFBgcICQoLDA0ODw==",
      generation: 1,
      fromBinding: FROM,
      toBinding: TO,
      signer: "tf:actor:agent:example.com/code-helper",
      privateKey: pair.privateKey,
    });
    const v = await verifySessionMigration({
      migration: m,
      publicKey: pair.publicKey,
      expectedSessionId: "DIFFERENT",
    });
    expect(v.ok).toBe(false);
  });

  test("migrationSigningBytes is stable", async () => {
    const pair = await ed25519Generate();
    const m = await migrateSession({
      sessionId: "AAECAwQFBgcICQoLDA0ODw==",
      generation: 1,
      fromBinding: FROM,
      toBinding: TO,
      signer: "tf:actor:agent:example.com/x",
      privateKey: pair.privateKey,
    });
    const a = migrationSigningBytes(m);
    const b = migrationSigningBytes({ ...m });
    expect(Buffer.from(a).toString("hex")).toBe(Buffer.from(b).toString("hex"));
  });
});

describe("Double ratchet", () => {
  test("rotates after maxMessages", () => {
    const initial = new Uint8Array(32).fill(1);
    const r = new Ratchet(initial, { maxMessages: 3, maxAgeSeconds: 600 });
    expect(r.generation()).toBe(0);
    expect(r.observeMessage()).toBe(false);
    expect(r.observeMessage()).toBe(false);
    expect(r.observeMessage()).toBe(true);
    expect(r.generation()).toBe(1);
    // Key changes
    expect(Buffer.from(r.key()).toString("hex")).not.toBe(Buffer.from(initial).toString("hex"));
  });

  test("rotate() forces immediate rotation", () => {
    const r = new Ratchet(new Uint8Array(32).fill(2));
    expect(r.generation()).toBe(0);
    r.rotate();
    expect(r.generation()).toBe(1);
    r.rotate();
    expect(r.generation()).toBe(2);
  });

  test("two ratchets initialized with the same seed produce the same sequence", () => {
    const seed = new Uint8Array(32).fill(7);
    const a = new Ratchet(seed);
    const b = new Ratchet(seed);
    a.rotate();
    b.rotate();
    expect(Buffer.from(a.key()).toString("hex")).toBe(Buffer.from(b.key()).toString("hex"));
  });

  test("rejects keys that are not 32 bytes", () => {
    expect(() => new Ratchet(new Uint8Array(16))).toThrow();
  });
});
