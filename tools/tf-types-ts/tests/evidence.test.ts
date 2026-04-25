import { describe, expect, test } from "bun:test";
import {
  anchorEvidenceBundle,
  assembleEvidenceBundle,
  ed25519Generate,
  evidenceBundleSigningBytes,
  MemoryAnchor,
  openEvidenceBundle,
  redactBundle,
  replayEvidence,
  rfc3161AnchorEvidence,
  sealEvidenceBundle,
  verifyEvidenceBundle,
  type ApprovalResponse,
  type PolicyDecision,
  type ProofEvent,
} from "../src/index";
import { x25519 } from "@noble/curves/ed25519";

const SOURCE = "tf:actor:agent:example.com/code-helper";
const ALICE = "tf:actor:human:example.com/alice";
const ISSUER = "tf:actor:service:example.com/tf-daemon";

function ev(id: string, ts: string, type: string, actor: string): ProofEvent {
  return {
    event_version: "1",
    id,
    type,
    actor_id: actor,
    timestamp: ts,
    level: "L3",
    signature: { algorithm: "ed25519", signer: actor, signature: "AAAA" },
  };
}

const events: ProofEvent[] = [
  ev("ev-1", "2026-04-24T12:00:30Z", "rpc.call", SOURCE),
  ev("ev-2", "2026-04-24T12:01:00Z", "approval.request", SOURCE),
  ev("ev-3", "2026-04-24T12:05:00Z", "approval.approve", ALICE),
  ev("ev-4", "2026-04-24T12:10:00Z", "rpc.call", SOURCE),
  // Out of window:
  ev("ev-5", "2026-04-24T13:30:00Z", "rpc.call", SOURCE),
];

const policyDecisions: PolicyDecision[] = [
  {
    decision_version: "1",
    policy_engine: "native",
    trust_domain: "example.com",
    subject: SOURCE,
    action: "firmware.install",
    decision: "escalate",
    rule_id: "escalate.firmware",
    reason: "firmware updates require quorum",
    evaluated_at: "2026-04-24T12:00:31Z",
  },
];

const approvals: ApprovalResponse[] = [
  {
    response_version: "1",
    request_id: "req-1",
    decision: "approve",
    responder: ALICE,
    signed_at: "2026-04-24T12:05:00Z",
    signature: { algorithm: "ed25519", signer: ALICE, signature: "AAAA" },
  },
];

describe("Evidence bundle assemble + verify", () => {
  test("assembles a bundle from events within the incident window", async () => {
    const issuer = await ed25519Generate();
    const result = await assembleEvidenceBundle({
      bundleId: "incident-1",
      trustDomain: "example.com",
      incident: {
        label: "test incident",
        startedAt: "2026-04-24T12:00:00Z",
        endedAt: "2026-04-24T13:00:00Z",
        domains: ["device-management"],
      },
      events,
      policyDecisions,
      approvals,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    expect(result.bundle.events.length).toBe(4);
    expect(result.skipped).toBe(1);
    expect(result.bundle.actors).toContain(ALICE);
    expect(result.bundle.actors).toContain(SOURCE);
    expect(result.bundle.signature.signature.length).toBeGreaterThan(0);
    const v = await verifyEvidenceBundle({
      bundle: result.bundle,
      issuerPublicKey: issuer.publicKey,
    });
    expect(v.outerSignatureOk).toBe(true);
    // No resolveEventSigner supplied → no per-event verification
    expect(v.eventsVerified).toBe(0);
    expect(v.eventsSkipped).toBe(0);
  });

  test("verify rejects tampered actors[]", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    bundle.actors = ["tf:actor:human:example.com/mallory"];
    const v = await verifyEvidenceBundle({ bundle, issuerPublicKey: issuer.publicKey });
    expect(v.outerSignatureOk).toBe(false);
    expect(v.ok).toBe(false);
  });

  test("filter by actor and event-type pattern", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      actorFilter: [ALICE],
      eventTypePattern: /^approval\./,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    expect(bundle.events.length).toBe(1);
    expect(bundle.events[0]!.id).toBe("ev-3");
  });

  test("evidenceBundleSigningBytes is stable", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const a = evidenceBundleSigningBytes(bundle);
    const b = evidenceBundleSigningBytes({ ...bundle });
    expect(Buffer.from(a).toString("hex")).toBe(Buffer.from(b).toString("hex"));
  });
});

describe("L4 sealing + opening", () => {
  test("evidence bundle round-trips through seal/open", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const recipientPriv = crypto.getRandomValues(new Uint8Array(32));
    const recipientPub = x25519.scalarMultBase(recipientPriv);
    const enc = await sealEvidenceBundle({
      bundle,
      recipients: [{ actor: ALICE, kemPublic: recipientPub }],
      signerPrivateKey: issuer.privateKey,
      signer: ISSUER,
    });
    const opened = await openEvidenceBundle({
      encrypted: enc,
      recipientPrivateKey: recipientPriv,
      recipientActor: ALICE,
      signerPublicKey: issuer.publicKey,
    });
    expect(opened.bundle_id).toBe("i");
    expect(opened.events.length).toBe(bundle.events.length);
  });
});

describe("L5 anchoring", () => {
  test("anchorEvidenceBundle attaches inclusion proofs from every backend", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const m1 = new MemoryAnchor();
    const m2 = new MemoryAnchor();
    const anchored = await anchorEvidenceBundle({ bundle, anchors: [m1, m2] });
    expect(anchored.anchors!.length).toBe(2);
    expect(anchored.anchors![0]!.kind).toBe("memory");
  });

  test("rfc3161AnchorEvidence records the TSA timestamp_response", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const tsaResponse = new TextEncoder().encode("OPAQUE-TSA-DER");
    const anchored = await rfc3161AnchorEvidence(bundle, async (_req) => tsaResponse);
    const anchor = anchored.anchors!.find((a) => a.kind === "rfc3161")!;
    expect(anchor.inclusion_proof).toBeDefined();
  });
});

describe("Timeline replay", () => {
  test("replayEvidence merges events + decisions + approvals in order", async () => {
    const issuer = await ed25519Generate();
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events,
      policyDecisions,
      approvals,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const tl = replayEvidence(bundle);
    expect(tl.length).toBeGreaterThan(events.filter((e) => e.timestamp <= "2026-04-24T13:00:00Z").length);
    // Sort is stable on timestamp; the policy.escalate entry should appear early.
    expect(tl[1]!.type).toBe("policy.escalate");
  });
});

describe("Redaction", () => {
  test("hash policy replaces a context field with a sha256 ref", async () => {
    const issuer = await ed25519Generate();
    const eventsWithCtx: ProofEvent[] = [
      {
        ...ev("ev-x", "2026-04-24T12:01:00Z", "rpc.call", SOURCE),
        context: { secret_arg: "supersecretvalue" },
      },
    ];
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events: eventsWithCtx,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const redacted = await redactBundle(
      bundle,
      [{ field: "secret_arg", policy: "hash" }],
      issuer.privateKey,
    );
    const ctx = redacted.events[0]!.context as Record<string, unknown>;
    expect(typeof ctx.secret_arg).toBe("string");
    expect((ctx.secret_arg as string).startsWith("sha256:")).toBe(true);
  });

  test("drop policy removes a context field", async () => {
    const issuer = await ed25519Generate();
    const eventsWithCtx: ProofEvent[] = [
      {
        ...ev("ev-x", "2026-04-24T12:01:00Z", "rpc.call", SOURCE),
        context: { keep_me: "ok", drop_me: "bad" },
      },
    ];
    const { bundle } = await assembleEvidenceBundle({
      bundleId: "i",
      trustDomain: "example.com",
      incident: { label: "x", startedAt: "2026-04-24T12:00:00Z", endedAt: "2026-04-24T13:00:00Z" },
      events: eventsWithCtx,
      issuer: ISSUER,
      privateKey: issuer.privateKey,
    });
    const redacted = await redactBundle(
      bundle,
      [{ field: "drop_me", policy: "drop" }],
      issuer.privateKey,
    );
    const ctx = redacted.events[0]!.context as Record<string, unknown>;
    expect(ctx.keep_me).toBe("ok");
    expect("drop_me" in ctx).toBe(false);
  });
});
