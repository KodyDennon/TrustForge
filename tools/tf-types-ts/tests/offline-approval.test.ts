import { describe, expect, test } from "bun:test";
import {
  ed25519Generate,
  signOfflineApprovalPacket,
  verifyOfflineApprovalPacket,
  type ApprovalRequest,
} from "../src/index";

const REQUEST: ApprovalRequest = {
  request_version: "1",
  id: "req-offline-1",
  actor: "tf:actor:agent:example.com/code-helper",
  action: "firmware.install",
  reason: "ship firmware v3 to gateway",
  created_at: "2026-04-24T12:00:00Z",
};

describe("Offline-signed approval packet", () => {
  test("round-trips approve packet with valid signature", async () => {
    const pair = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: REQUEST,
      decision: "approve",
      responder: "tf:actor:human:example.com/alice",
      privateKey: pair.privateKey,
      transportHint: "usb",
    });
    const verified = await verifyOfflineApprovalPacket({
      packet,
      publicKey: pair.publicKey,
    });
    expect(verified.ok).toBe(true);
    expect(verified.response?.decision).toBe("approve");
    expect(verified.ceremony?.kind).toBe("offline-signed-packet");
    expect(verified.ceremony?.transport_hint).toBe("usb");
  });

  test("rejects a packet whose signature does not match", async () => {
    const pair = await ed25519Generate();
    const otherPair = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: REQUEST,
      decision: "approve",
      responder: "tf:actor:human:example.com/alice",
      privateKey: pair.privateKey,
      transportHint: "qr-code",
    });
    const verified = await verifyOfflineApprovalPacket({
      packet,
      publicKey: otherPair.publicKey,
    });
    expect(verified.ok).toBe(false);
    expect(verified.reason).toContain("signature");
  });

  test("rejects a packet older than maxAgeSeconds", async () => {
    const pair = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: REQUEST,
      decision: "approve",
      responder: "tf:actor:human:example.com/alice",
      privateKey: pair.privateKey,
      transportHint: "file-drop",
      respondedAt: "2026-04-23T00:00:00Z",
    });
    const verified = await verifyOfflineApprovalPacket({
      packet,
      publicKey: pair.publicKey,
      now: "2026-04-25T00:00:00Z",
      maxAgeSeconds: 3600,
    });
    expect(verified.ok).toBe(false);
    expect(verified.reason).toContain("older than");
  });

  test("rejects a packet whose responder differs from the signer", async () => {
    const pair = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: REQUEST,
      decision: "approve",
      responder: "tf:actor:human:example.com/alice",
      privateKey: pair.privateKey,
      transportHint: "usb",
    });
    packet.signature.signer = "tf:actor:human:example.com/mallory";
    const verified = await verifyOfflineApprovalPacket({
      packet,
      publicKey: pair.publicKey,
    });
    expect(verified.ok).toBe(false);
    expect(verified.reason).toContain("signer");
  });

  test("rejects deny packets that try to forge the request body", async () => {
    const pair = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: REQUEST,
      decision: "deny",
      responder: "tf:actor:human:example.com/alice",
      privateKey: pair.privateKey,
      transportHint: "manual",
    });
    // tamper the request body after signing
    packet.request = { ...packet.request, action: "shell.exec" };
    const verified = await verifyOfflineApprovalPacket({
      packet,
      publicKey: pair.publicKey,
    });
    expect(verified.ok).toBe(false);
  });
});
