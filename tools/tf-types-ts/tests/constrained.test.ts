/**
 * Tests for the constrained-mode runtime primitives:
 *   - PacketReceiver (sliding-window nonce cache)
 *   - OfflineRevocationListRuntime
 *   - delivery receipts
 *   - proof-of-forwarding
 */

import { describe, expect, test } from "bun:test";
import {
  PacketReceiver,
  OfflineRevocationListRuntime,
  signDeliveryReceipt,
  verifyDeliveryReceipt,
  signProofOfForwarding,
  verifyProofOfForwarding,
  signOfflineRevocationList,
} from "../src/core/constrained";
import { ed25519Generate, signPacket } from "../src/index";
import type { OfflineRevocationList } from "../src/generated/offline-revocation-list";

describe("PacketReceiver — sliding-window nonce cache", () => {
  test("first observation accepted; replay rejected", async () => {
    const pair = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-A",
      source: "tf:actor:agent:example.com/x",
      destination: "tf:actor:service:example.com/d",
      priority: "P3",
      payload: new TextEncoder().encode("hi"),
      privateKey: pair.privateKey,
      signer: "tf:actor:agent:example.com/x",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const recv = new PacketReceiver({ now: () => "2026-04-24T13:00:00Z" });
    expect(recv.observe(p).kind).toBe("accept");
    expect(recv.observe(p)).toEqual({ kind: "reject", reason: "replay" });
  });

  test("expired packet rejected; cache honours window size with LRU eviction", async () => {
    const pair = await ed25519Generate();
    const expired = await signPacket({
      packetId: "pkt-old",
      source: "tf:actor:agent:example.com/x",
      destination: "tf:actor:service:example.com/d",
      priority: "P3",
      payload: new TextEncoder().encode("a"),
      expiresAt: "2026-04-23T00:00:00Z",
      privateKey: pair.privateKey,
      signer: "tf:actor:agent:example.com/x",
      createdAt: "2026-04-22T00:00:00Z",
    });
    const recv = new PacketReceiver({ windowSize: 2, now: () => "2026-04-24T12:00:00Z" });
    expect(recv.observe(expired)).toEqual({ kind: "reject", reason: "expired" });
    // Push 3 distinct packets through a window-of-2; oldest evicted.
    for (let i = 0; i < 3; i++) {
      const p = await signPacket({
        packetId: `pkt-${i}`,
        source: "tf:actor:agent:example.com/x",
        destination: "tf:actor:service:example.com/d",
        priority: "P3",
        payload: new TextEncoder().encode(`p${i}`),
        privateKey: pair.privateKey,
        signer: "tf:actor:agent:example.com/x",
        createdAt: "2026-04-24T11:00:00Z",
      });
      expect(recv.observe(p).kind).toBe("accept");
    }
    expect(recv.size()).toBe(2);
  });

  test("future-dated packet rejected", async () => {
    const pair = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-future",
      source: "tf:actor:agent:example.com/x",
      destination: "tf:actor:service:example.com/d",
      priority: "P3",
      payload: new TextEncoder().encode("hi"),
      privateKey: pair.privateKey,
      signer: "tf:actor:agent:example.com/x",
      createdAt: "2099-04-24T12:00:00Z",
    });
    const recv = new PacketReceiver({ now: () => "2026-04-24T12:00:00Z" });
    expect(recv.observe(p)).toEqual({ kind: "reject", reason: "future-dated" });
  });
});

describe("OfflineRevocationListRuntime", () => {
  test("verifies signature, indexes entries, refuses expired list", async () => {
    const issuer = await ed25519Generate();
    const draft: Omit<OfflineRevocationList, "signature"> = {
      list_version: "1",
      trust_domain: "example.com",
      issued_at: "2026-04-24T00:00:00Z",
      valid_until: "2026-04-30T00:00:00Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      revoked: [
        { kind: "actor", id: "tf:actor:agent:example.com/bad", reason: "compromised" },
        { kind: "key", id: "kid-42" },
      ],
    };
    const signed = await signOfflineRevocationList({
      list: draft,
      privateKey: issuer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    const runtime = await OfflineRevocationListRuntime.load(signed, {
      issuerPublicKey: issuer.publicKey,
      now: "2026-04-25T00:00:00Z",
    });
    expect(
      runtime.isRevoked({ kind: "actor", id: "tf:actor:agent:example.com/bad" }),
    ).toBeDefined();
    expect(runtime.isRevoked({ kind: "key", id: "kid-42" })).toBeDefined();
    expect(runtime.isRevoked({ kind: "actor", id: "tf:actor:agent:example.com/ok" })).toBeUndefined();
    expect(runtime.metadata().issuer).toBe("tf:actor:service:example.com/tf-daemon");

    await expect(
      OfflineRevocationListRuntime.load(signed, {
        issuerPublicKey: issuer.publicKey,
        now: "2026-05-15T00:00:00Z",
      }),
    ).rejects.toThrow(/expired/);
  });

  test("rejects forged signature", async () => {
    const issuer = await ed25519Generate();
    const otherIssuer = await ed25519Generate();
    const signed = await signOfflineRevocationList({
      list: {
        list_version: "1",
        trust_domain: "example.com",
        issued_at: "2026-04-24T00:00:00Z",
        valid_until: "2026-04-30T00:00:00Z",
        issuer: "tf:actor:service:example.com/tf-daemon",
        revoked: [],
      },
      privateKey: issuer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    await expect(
      OfflineRevocationListRuntime.load(signed, {
        issuerPublicKey: otherIssuer.publicKey,
        now: "2026-04-25T00:00:00Z",
      }),
    ).rejects.toThrow(/signature did not verify/);
  });
});

describe("Delivery receipts", () => {
  test("round-trip: receiver signs, sender verifies", async () => {
    const sender = await ed25519Generate();
    const receiver = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-deliver-1",
      source: "tf:actor:agent:example.com/sender",
      destination: "tf:actor:agent:example.com/receiver",
      priority: "P3",
      payload: new TextEncoder().encode("payload"),
      privateKey: sender.privateKey,
      signer: "tf:actor:agent:example.com/sender",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const receipt = await signDeliveryReceipt({
      packet: p,
      receiver: "tf:actor:agent:example.com/receiver",
      receivedAt: "2026-04-24T12:01:00Z",
      privateKey: receiver.privateKey,
    });
    const v = await verifyDeliveryReceipt(receipt, p, receiver.publicKey);
    expect(v.ok).toBe(true);
  });

  test("rejects receipt for a different packet", async () => {
    const sender = await ed25519Generate();
    const receiver = await ed25519Generate();
    const p1 = await signPacket({
      packetId: "pkt-1",
      source: "tf:actor:agent:example.com/sender",
      destination: "tf:actor:agent:example.com/receiver",
      priority: "P3",
      payload: new TextEncoder().encode("a"),
      privateKey: sender.privateKey,
      signer: "tf:actor:agent:example.com/sender",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const p2 = await signPacket({
      packetId: "pkt-2",
      source: "tf:actor:agent:example.com/sender",
      destination: "tf:actor:agent:example.com/receiver",
      priority: "P3",
      payload: new TextEncoder().encode("b"),
      privateKey: sender.privateKey,
      signer: "tf:actor:agent:example.com/sender",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const receipt = await signDeliveryReceipt({
      packet: p1,
      receiver: "tf:actor:agent:example.com/receiver",
      privateKey: receiver.privateKey,
    });
    const v = await verifyDeliveryReceipt(receipt, p2, receiver.publicKey);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("packet_id mismatch");
  });
});

describe("Proof of forwarding", () => {
  test("relay signs, receiver verifies; tamper detected", async () => {
    const sender = await ed25519Generate();
    const relay = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-relay-1",
      source: "tf:actor:agent:example.com/sender",
      destination: "tf:actor:agent:example.com/dest",
      priority: "P3",
      payload: new TextEncoder().encode("payload"),
      privateKey: sender.privateKey,
      signer: "tf:actor:agent:example.com/sender",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const proof = await signProofOfForwarding({
      packet: p,
      relay: "tf:actor:relay:example.com/edge",
      forwardedAt: "2026-04-24T12:01:00Z",
      hopCount: 1,
      privateKey: relay.privateKey,
    });
    const v = await verifyProofOfForwarding(proof, p, relay.publicKey);
    expect(v.ok).toBe(true);

    // Forge by editing forwarded_at — signature should now mismatch.
    const tampered = { ...proof, forwarded_at: "2027-01-01T00:00:00Z" };
    const v2 = await verifyProofOfForwarding(tampered, p, relay.publicKey);
    expect(v2.ok).toBe(false);
  });
});
