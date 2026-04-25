/**
 * B6 evidence pipeline correctness:
 *   - verifyEvidenceBundle requires a resolver OR explicit opt-out;
 *     silent skip is no longer valid.
 *   - openBundle requires signerPublicKey OR explicit acceptUnsignedBundle;
 *     and verifies the signature BEFORE decrypting.
 *   - assembleEvidenceBundle recomputes parent_hash on the filtered set so
 *     verifyChain succeeds.
 *   - replay timeline interleaves Z and +00:00 ISO formats correctly.
 *   - signOfflineApprovalPacket includes nonce + transport_hint in the
 *     signed payload; verify checks consumed nonces.
 *   - ApprovalQueue rejects duplicate-id pushes instead of orphaning the
 *     prior promise.
 */
import { describe, expect, test } from "bun:test";
import {
  ApprovalQueue,
  ApprovalQueueDuplicateError,
  assembleEvidenceBundle,
  ed25519Generate,
  openBundle,
  replayEvidence,
  sealEvidenceBundle,
  signOfflineApprovalPacket,
  verifyChain,
  verifyEvidenceBundle,
  verifyOfflineApprovalPacket,
  type EvidenceBundle,
  type ProofEvent,
} from "../src/index";

function buildSignedEvent(args: {
  id: string;
  type: string;
  ts: string;
  signer: string;
}): ProofEvent {
  return {
    event_version: "1",
    id: args.id,
    type: args.type,
    actor_id: args.signer,
    timestamp: args.ts,
    level: "L1",
    signature: { algorithm: "ed25519", signer: args.signer, signature: "AAAA" },
  } as ProofEvent;
}

describe("B6 — verifyEvidenceBundle fail-closed default", () => {
  test("missing resolveEventSigner → fails closed (was silent-skip)", async () => {
    const issuer = await ed25519Generate();
    const result = await assembleEvidenceBundle({
      events: [
        buildSignedEvent({
          id: "e1",
          type: "guard.check",
          ts: "2026-04-25T00:01:00Z",
          signer: "tf:actor:agent:example.com/x",
        }),
      ],
      bundleId: "ev-b6-1",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T00:00:00Z" },
      issuer: "tf:actor:service:example.com/auditor",
      privateKey: issuer.privateKey,
    });
    const verdict = await verifyEvidenceBundle({
      bundle: result.bundle,
      issuerPublicKey: issuer.publicKey,
      // NO resolveEventSigner, NO skipPerEventVerification.
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("resolveEventSigner");
  });

  test("explicit skipPerEventVerification opts out cleanly", async () => {
    const issuer = await ed25519Generate();
    const result = await assembleEvidenceBundle({
      events: [
        buildSignedEvent({
          id: "e1",
          type: "guard.check",
          ts: "2026-04-25T00:01:00Z",
          signer: "tf:actor:agent:example.com/x",
        }),
      ],
      bundleId: "ev-b6-2",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T00:00:00Z" },
      issuer: "tf:actor:service:example.com/auditor",
      privateKey: issuer.privateKey,
    });
    const verdict = await verifyEvidenceBundle({
      bundle: result.bundle,
      issuerPublicKey: issuer.publicKey,
      skipPerEventVerification: true,
    });
    expect(verdict.ok).toBe(true);
  });
});

describe("B6 — openBundle requires signerPublicKey by default", () => {
  test("omitting signerPublicKey throws", async () => {
    // Build a real sealed bundle so we have something to feed openBundle.
    const signer = await ed25519Generate();
    const recipient = await ed25519Generate();
    const assembled = await assembleEvidenceBundle({
      events: [
        buildSignedEvent({
          id: "e1",
          type: "guard.check",
          ts: "2026-04-25T00:01:00Z",
          signer: "tf:actor:agent:example.com/x",
        }),
      ],
      bundleId: "b6-bundle",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T00:00:00Z" },
      issuer: "tf:actor:service:example.com/auditor",
      privateKey: signer.privateKey,
    });
    const sealed = await sealEvidenceBundle({
      bundle: assembled.bundle,
      signer: "tf:actor:service:example.com/auditor",
      signerPrivateKey: signer.privateKey,
      recipients: [{ actor: "tf:actor:human:example.com/auditor-2", kemPublic: recipient.publicKey }],
    });
    let threw: Error | undefined;
    try {
      await openBundle({
        encrypted: sealed,
        recipientPrivateKey: recipient.privateKey,
        recipientActor: "tf:actor:human:example.com/auditor-2",
      });
    } catch (err) {
      threw = err as Error;
    }
    expect(threw?.message).toContain("openBundle requires signerPublicKey");
  });
});

describe("B6 — assembleEvidenceBundle recomputes parent_hash", () => {
  test("the assembled chain verifies even when intermediate events were dropped", async () => {
    const signer = await ed25519Generate();
    const events: ProofEvent[] = [
      {
        event_version: "1",
        id: "e1",
        type: "guard.check",
        actor_id: "tf:actor:agent:example.com/x",
        timestamp: "2026-04-25T00:01:00Z",
        level: "L1",
        // No parent_hash on the first event.
        signature: { algorithm: "ed25519", signer: "x", signature: "AAAA" },
      },
      {
        event_version: "1",
        id: "e2",
        type: "approval.request",
        actor_id: "tf:actor:agent:example.com/x",
        timestamp: "2026-04-25T00:02:00Z",
        level: "L1",
        // Stale parent_hash from a different (filtered-out) ancestor.
        parent_hash: "sha256:dead",
        signature: { algorithm: "ed25519", signer: "x", signature: "AAAA" },
      },
    ];
    const result = await assembleEvidenceBundle({
      events,
      bundleId: "ev-asm",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T00:00:00Z" },
      issuer: "tf:actor:service:example.com/auditor",
      privateKey: signer.privateKey,
    });
    // verifyChain should succeed because assembleEvidenceBundle re-linked.
    expect(() => verifyChain(result.bundle.events as unknown as Parameters<typeof verifyChain>[0])).not.toThrow();
  });
});

describe("B6 — replayEvidence date parse", () => {
  test("Z and +00:00 ISO formats interleave correctly", () => {
    const events: ProofEvent[] = [
      {
        event_version: "1",
        id: "a",
        type: "x",
        actor_id: "x",
        timestamp: "2026-04-25T10:00:01+00:00",
        level: "L1",
        signature: { algorithm: "ed25519", signer: "x", signature: "AAAA" },
      },
      {
        event_version: "1",
        id: "b",
        type: "x",
        actor_id: "x",
        timestamp: "2026-04-25T10:00:00.500Z",
        level: "L1",
        signature: { algorithm: "ed25519", signer: "x", signature: "AAAA" },
      },
    ];
    const bundle: EvidenceBundle = {
      evidence_version: "1",
      bundle_id: "x",
      trust_domain: "example.com",
      incident: { label: "x", started_at: "2026-04-25T00:00:00Z" },
      actors: ["x"],
      events,
      policy_decisions: [],
      approvals: [],
      ceremonies: [],
      issued_at: "2026-04-25T11:00:00Z",
      issuer: "x",
      level: "L1",
      signature: { algorithm: "ed25519", signer: "x", signature: "AAAA" },
    } as unknown as EvidenceBundle;
    const tl = replayEvidence(bundle);
    expect(tl.length).toBe(2);
    // 10:00:00.500 (event b) comes before 10:00:01 (event a) by date.
    // Lexicographic sort would put "10:00:00.500Z" AFTER "10:00:01+00:00"
    // because `.` (0x2E) > `+` (0x2B); B6's date-parse fix puts them
    // back in real chronological order.
    expect(tl[0]!.timestamp).toBe("2026-04-25T10:00:00.500Z");
    expect(tl[1]!.timestamp).toBe("2026-04-25T10:00:01+00:00");
  });
});

describe("B6 — offline approval nonce + replay defense", () => {
  test("signed packet includes nonce + transport_hint; replays are rejected", async () => {
    const responder = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: {
        request_version: "1",
        id: "req-b6",
        actor: "tf:actor:agent:example.com/x",
        action: "fs.write",
        danger_tags: [],
        reason: "test",
        created_at: "2026-04-25T00:00:00Z",
      },
      decision: "approve",
      responder: "tf:actor:human:example.com/auditor",
      privateKey: responder.privateKey,
      transportHint: "qr-code",
    });
    expect(packet.nonce).toBeDefined();
    expect(packet.nonce.length).toBeGreaterThan(10);

    const consumed = new Set<string>();
    const isConsumed = (k: { responder: string; request_id: string; nonce: string }) =>
      consumed.has(`${k.responder}|${k.request_id}|${k.nonce}`);
    const v1 = await verifyOfflineApprovalPacket({
      packet,
      publicKey: responder.publicKey,
      isConsumed,
    });
    expect(v1.ok).toBe(true);
    consumed.add(`${packet.responder}|${packet.request.id}|${packet.nonce}`);

    const v2 = await verifyOfflineApprovalPacket({
      packet,
      publicKey: responder.publicKey,
      isConsumed,
    });
    expect(v2.ok).toBe(false);
    expect(v2.reason).toContain("replay");
  });

  test("tampering transport_hint after signing invalidates the signature", async () => {
    const responder = await ed25519Generate();
    const packet = await signOfflineApprovalPacket({
      request: {
        request_version: "1",
        id: "req-b6-2",
        actor: "tf:actor:agent:example.com/x",
        action: "fs.write",
        danger_tags: [],
        reason: "test",
        created_at: "2026-04-25T00:00:00Z",
      },
      decision: "approve",
      responder: "tf:actor:human:example.com/auditor",
      privateKey: responder.privateKey,
      transportHint: "qr-code",
    });
    const tampered = { ...packet, transport_hint: "manual" as const };
    const v = await verifyOfflineApprovalPacket({ packet: tampered, publicKey: responder.publicKey });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain("signature");
  });
});

describe("B6 — ApprovalQueue duplicate id rejection", () => {
  test("re-pushing the same id throws ApprovalQueueDuplicateError", () => {
    const queue = new ApprovalQueue({ defaultTimeoutMs: 60_000 });
    queue.push({
      request_version: "1",
      id: "dup",
      actor: "tf:actor:agent:example.com/x",
      action: "fs.write",
      danger_tags: [],
      reason: "test",
      created_at: "2026-04-25T00:00:00Z",
    });
    let threw: Error | undefined;
    try {
      queue.push({
        request_version: "1",
        id: "dup",
        actor: "tf:actor:agent:example.com/x",
        action: "fs.write",
        danger_tags: [],
        reason: "test",
        created_at: "2026-04-25T00:00:00Z",
      });
    } catch (err) {
      threw = err as Error;
    }
    expect(threw).toBeInstanceOf(ApprovalQueueDuplicateError);
    queue.drainDeny("end");
  });
});
