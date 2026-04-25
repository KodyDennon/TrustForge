/**
 * Compliance evidence pipeline (TF-0012).
 *
 * `assembleEvidenceBundle` reads a `.tflog`, filters events by
 * timestamp window / actor / event-type, joins matching policy
 * decisions and approvals (supplied by the caller), and produces an
 * `EvidenceBundle` ready to seal.
 *
 * `sealEvidenceBundle` produces an L4 encrypted bundle (per recipient,
 * X25519+HKDF-wrapped data keys, ChaCha20-Poly1305 sealing). Pairs
 * with `openEvidenceBundle`.
 *
 * `anchorEvidenceBundle` submits a bundle to one or more anchors
 * (RFC 6962, sigstore Rekor, RFC 3161 timestamp authority, in-memory
 * test) and stores the inclusion proofs back on the bundle.
 *
 * `verifyEvidenceBundle` re-checks the outer signature, every embedded
 * proof event signature, the chain hash, the manifest hash on each
 * policy decision, and any anchor inclusion proofs the caller passes.
 *
 * `replayEvidence` walks events in order, returns a structured
 * timeline that audits can rendering.
 *
 * `redactBundle` applies a per-field redaction policy (keep / hash /
 * drop) so an evidence bundle can be shared with an external auditor
 * without leaking secrets.
 */

import { readFileSync } from "node:fs";

import type { EvidenceBundle } from "../generated/evidence-bundle.js";
import type { ProofEvent } from "../generated/proof-event.js";
import type { ProofBundle } from "../generated/proof-bundle.js";
import type { PolicyDecision } from "../generated/policy-decision.js";
import type { ApprovalResponse } from "../generated/approval-response.js";
import type { ApprovalCeremony } from "../generated/approval-ceremony.js";
import type { ActorId, ProofLevel, SignatureEnvelope, Timestamp } from "../generated/_common.js";
import { canonicalize } from "./canonical.js";
import { sha256, ed25519Sign, ed25519Verify } from "./crypto.js";
import { readTflog } from "./format.js";
import { verifyChain } from "./chain.js";
import {
  type AnchorBackend,
  type EncryptedProofBundle,
  encryptedSigningBytes,
  openBundle,
  sealBundle,
  type BundleRecipient,
} from "./bundle.js";
import { buildRfc3161Request } from "./bundle.js";

export type IncidentDomain =
  | "msp"
  | "healthcare"
  | "finance"
  | "government"
  | "maritime"
  | "critical-infrastructure"
  | "remote-support"
  | "enterprise-ai"
  | "device-management"
  | "firmware-control";

export interface AssembleEvidenceArgs {
  bundleId: string;
  trustDomain: string;
  incident: {
    label: string;
    startedAt: Timestamp;
    endedAt?: Timestamp;
    domains?: IncidentDomain[];
    description?: string;
  };
  /** Path to a .tflog file or pre-loaded events. */
  tflogPath?: string;
  events?: ProofEvent[];
  /** Filter: only include events whose actor_id is in this list. */
  actorFilter?: ActorId[];
  /** Filter: only include events whose `type` matches this regex. */
  eventTypePattern?: RegExp;
  policyDecisions?: PolicyDecision[];
  approvals?: ApprovalResponse[];
  ceremonies?: ApprovalCeremony[];
  quorumOutcomes?: EvidenceBundle["quorum_outcomes"];
  issuer: ActorId;
  privateKey: Uint8Array;
}

export interface AssembleEvidenceResult {
  bundle: EvidenceBundle;
  /** Number of events the source tflog contained that fell outside the
   *  filters and were skipped. */
  skipped: number;
}

export function evidenceBundleSigningBytes(b: EvidenceBundle): Uint8Array {
  const { signature: _signature, ...rest } = b;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

/** Compute the canonical hash of an event for chain linking. Mirrors
 *  ProofChain.hashRef in proof-event-builder. */
function eventHashRefForChain(ev: ProofEvent): string {
  const unsigned = { ...ev, signature: undefined };
  const digest = sha256(new TextEncoder().encode(canonicalize(unsigned as unknown)));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

/** Assemble an evidence bundle from a tflog + caller-supplied policy /
 *  approval / ceremony records. The bundle is fully signed before
 *  return; pass it to `sealEvidenceBundle` for L4 encryption or
 *  `anchorEvidenceBundle` for L5 transparency anchoring. */
export async function assembleEvidenceBundle(
  args: AssembleEvidenceArgs,
): Promise<AssembleEvidenceResult> {
  let candidateEvents: ProofEvent[];
  if (args.events) {
    candidateEvents = args.events.slice();
  } else if (args.tflogPath) {
    const raw = readFileSync(args.tflogPath);
    candidateEvents = readTflog(new Uint8Array(raw)) as unknown as ProofEvent[];
  } else {
    throw new Error("assembleEvidenceBundle requires `events` or `tflogPath`");
  }

  const start = args.incident.startedAt;
  const end = args.incident.endedAt;
  const actorSet = args.actorFilter ? new Set(args.actorFilter) : null;
  const re = args.eventTypePattern;
  let skipped = 0;
  const events: ProofEvent[] = [];
  for (const ev of candidateEvents) {
    if (ev.timestamp < start) {
      skipped += 1;
      continue;
    }
    if (end && ev.timestamp > end) {
      skipped += 1;
      continue;
    }
    if (actorSet && !actorSet.has(ev.actor_id)) {
      skipped += 1;
      continue;
    }
    if (re && !re.test(ev.type)) {
      skipped += 1;
      continue;
    }
    events.push(ev);
  }
  if (events.length === 0) {
    throw new Error("evidence bundle requires at least one matching event");
  }

  // Recompute parent_hash on the filtered set so verifyChain succeeds
  // on a bundle assembled from a sparser tflog. (Pre-B6 the assembler
  // preserved the source-log chain; verifyChain then failed any time
  // the filter dropped intermediate events.)
  for (let i = 0; i < events.length; i++) {
    const prev = i === 0 ? undefined : events[i - 1]!;
    const prevHash = prev ? eventHashRefForChain(prev) : undefined;
    events[i] = { ...events[i]!, parent_hash: prevHash };
  }

  const distinctActors = Array.from(new Set(events.map((e) => e.actor_id))).sort();
  const level = highestLevel(events);

  const draft: EvidenceBundle = {
    evidence_version: "1",
    bundle_id: args.bundleId,
    trust_domain: args.trustDomain,
    incident: {
      label: args.incident.label,
      started_at: args.incident.startedAt,
      ended_at: args.incident.endedAt,
      domains: args.incident.domains,
      description: args.incident.description,
    },
    actors: distinctActors,
    events,
    policy_decisions: args.policyDecisions ?? [],
    approvals: args.approvals ?? [],
    ceremonies: args.ceremonies,
    quorum_outcomes: args.quorumOutcomes,
    level,
    issued_at: new Date().toISOString(),
    issuer: args.issuer,
    signature: { algorithm: "ed25519", signer: args.issuer, signature: "" } as SignatureEnvelope,
  };
  const digest = evidenceBundleSigningBytes(draft);
  const sig = await ed25519Sign(digest, args.privateKey);
  draft.signature = {
    algorithm: "ed25519",
    signer: args.issuer,
    signature: Buffer.from(sig).toString("base64"),
  };

  return { bundle: draft, skipped };
}

function highestLevel(events: ProofEvent[]): ProofLevel {
  const order: ProofLevel[] = ["L0", "L1", "L2", "L3", "L4", "L5"];
  let max = 0;
  for (const ev of events) {
    const idx = order.indexOf(ev.level);
    if (idx > max) max = idx;
  }
  return order[max]!;
}

/* -------------------------------------------------------------------------- */
/*  L4 encrypted evidence                                                     */
/* -------------------------------------------------------------------------- */

export interface SealEvidenceArgs {
  bundle: EvidenceBundle;
  recipients: BundleRecipient[];
  signerPrivateKey: Uint8Array;
  signer: ActorId;
}

/** Wrap an evidence bundle into an L4 encrypted ProofBundle so it can
 *  be handed to legal/auditors without leaking secrets. The resulting
 *  envelope is per-recipient sealed; each recipient holds an X25519
 *  private key and decrypts via `openEvidenceBundle`. */
export async function sealEvidenceBundle(args: SealEvidenceArgs): Promise<EncryptedProofBundle> {
  // The encrypted bundle wraps the canonical evidence bundle as a
  // ProofBundle (the existing sealBundle understands ProofBundle).
  // We re-shape the evidence bundle into a single-event ProofBundle
  // synthetic wrapper for sealing — the real evidence sits in
  // `wrapped.events[0].context`.
  const synthetic: ProofBundle = {
    bundle_version: "1",
    events: [
      {
        event_version: "1",
        id: `evidence-${args.bundle.bundle_id}`,
        type: "evidence.bundle",
        actor_id: args.bundle.issuer,
        timestamp: args.bundle.issued_at,
        level: args.bundle.level ?? "L4",
        context: args.bundle as unknown as Record<string, unknown>,
        signature: args.bundle.signature,
      },
    ],
    signature: args.bundle.signature,
  };
  return sealBundle({
    bundle: synthetic,
    recipients: args.recipients,
    level: "L4",
    signerPrivateKey: args.signerPrivateKey,
    signer: args.signer,
  });
}

export interface OpenEvidenceArgs {
  encrypted: EncryptedProofBundle;
  recipientPrivateKey: Uint8Array;
  recipientActor: ActorId;
  signerPublicKey?: Uint8Array;
}

export async function openEvidenceBundle(args: OpenEvidenceArgs): Promise<EvidenceBundle> {
  const inner = await openBundle({
    encrypted: args.encrypted,
    recipientPrivateKey: args.recipientPrivateKey,
    recipientActor: args.recipientActor,
    signerPublicKey: args.signerPublicKey,
  });
  const ev = inner.events?.[0];
  if (!ev || !ev.context) throw new Error("encrypted bundle missing evidence context");
  return ev.context as unknown as EvidenceBundle;
}

/* -------------------------------------------------------------------------- */
/*  L5 anchoring                                                              */
/* -------------------------------------------------------------------------- */

export interface AnchorEvidenceArgs {
  bundle: EvidenceBundle;
  anchors: AnchorBackend[];
}

/** Submit the bundle to every anchor and stamp the inclusion proofs
 *  back onto `bundle.anchors`. The bundle's outer signature does not
 *  need to be re-issued — anchor entries are appended metadata. */
export async function anchorEvidenceBundle(args: AnchorEvidenceArgs): Promise<EvidenceBundle> {
  const bytes = new TextEncoder().encode(canonicalize(args.bundle as unknown));
  const next = { ...args.bundle, anchors: (args.bundle.anchors ?? []).slice() } as EvidenceBundle;
  for (const a of args.anchors) {
    const proof = await a.submit(bytes);
    next.anchors!.push({
      kind: a.kind,
      url: a.url,
      inclusion_proof: proof.inclusion_proof,
    });
  }
  return next;
}

/** Submit a bundle digest to a TSA via the supplied callback (which
 *  receives a DER-encoded TimeStampReq and must return the TSA's
 *  TimeStampResp). The result is appended as an `rfc3161` anchor. */
export async function rfc3161AnchorEvidence(
  bundle: EvidenceBundle,
  tsaSubmit: (req: Uint8Array) => Promise<Uint8Array>,
): Promise<EvidenceBundle> {
  const bytes = new TextEncoder().encode(canonicalize(bundle as unknown));
  const req = buildRfc3161Request(bytes);
  const resp = await tsaSubmit(req);
  return {
    ...bundle,
    anchors: [
      ...(bundle.anchors ?? []),
      {
        kind: "rfc3161",
        inclusion_proof: { timestamp_response: Buffer.from(resp).toString("base64") },
      },
    ],
  } as EvidenceBundle;
}

/* -------------------------------------------------------------------------- */
/*  Verification                                                              */
/* -------------------------------------------------------------------------- */

export interface VerifyEvidenceArgs {
  bundle: EvidenceBundle;
  /** Public key matching `bundle.issuer`. */
  issuerPublicKey: Uint8Array;
  /** Optional verifiers for individual anchors (caller-supplied; the
   *  helper just iterates over `bundle.anchors`). */
  verifyAnchor?: (
    anchor: NonNullable<EvidenceBundle["anchors"]>[number],
    bundleBytes: Uint8Array,
  ) => Promise<boolean>;
  /** Event-signer key resolver. Returns null when the verifier doesn't
   *  know that signer (the event signature for that event is then
   *  treated as unverified — the bundle fails-closed unless the caller
   *  opted into `skipPerEventVerification`). */
  resolveEventSigner?: (signer: ActorId) => Promise<Uint8Array | null>;
  /** Explicit opt-out: skip per-event signature verification entirely.
   *  Pre-B6 the verifier silently skipped events when no resolver was
   *  supplied; auditors who didn't notice `eventsSkipped` accepted
   *  fake-signer events. Fail-closed is the default; this flag is
   *  meant only for replay tooling that has already verified
   *  out-of-band. */
  skipPerEventVerification?: boolean;
}

export interface VerifyEvidenceResult {
  ok: boolean;
  reason?: string;
  outerSignatureOk: boolean;
  /** Number of events whose signature matched. */
  eventsVerified: number;
  /** Events whose signer key was unknown to the verifier. */
  eventsSkipped: number;
  /** Anchor-by-anchor verdicts. */
  anchors: Array<{ kind: string; ok: boolean }>;
  /** True if the full chain (parent_hash links) matches each successive event. */
  chainOk: boolean;
}

export async function verifyEvidenceBundle(
  args: VerifyEvidenceArgs,
): Promise<VerifyEvidenceResult> {
  const result: VerifyEvidenceResult = {
    ok: false,
    outerSignatureOk: false,
    eventsVerified: 0,
    eventsSkipped: 0,
    anchors: [],
    chainOk: false,
  };

  const digest = evidenceBundleSigningBytes(args.bundle);
  const sigBytes = new Uint8Array(Buffer.from(args.bundle.signature.signature, "base64"));
  result.outerSignatureOk = await ed25519Verify(args.issuerPublicKey, digest, sigBytes);
  if (!result.outerSignatureOk) {
    result.reason = "outer signature did not verify";
    return result;
  }

  // Per-event signature verification. Fail-closed default (post-B6):
  // a caller MUST either supply `resolveEventSigner` so the verifier
  // can check each event signature OR explicitly opt out via
  // `skipPerEventVerification: true`. The previous silent-skip
  // behavior let bundles with unknown signers pass auditors.
  if (args.skipPerEventVerification) {
    // Caller acknowledges this bundle's events are out-of-band-verified.
  } else if (args.resolveEventSigner) {
    for (const ev of args.bundle.events) {
      const pk = await args.resolveEventSigner(ev.signature.signer);
      if (!pk) {
        result.eventsSkipped += 1;
        result.reason = `event ${ev.id} signer ${ev.signature.signer} unknown to verifier (no resolver entry)`;
        return result;
      }
      const eventDigest = sha256(
        new TextEncoder().encode(canonicalize({ ...ev, signature: undefined } as unknown)),
      );
      const eventSig = new Uint8Array(Buffer.from(ev.signature.signature, "base64"));
      const okEv = await ed25519Verify(pk, eventDigest, eventSig);
      if (okEv) result.eventsVerified += 1;
      else {
        result.reason = `event ${ev.id} signature did not verify`;
        return result;
      }
    }
  } else if (args.bundle.events.length > 0) {
    result.reason =
      "verifyEvidenceBundle requires resolveEventSigner OR skipPerEventVerification:true";
    return result;
  }

  // Hash chain — verifyChain throws on the first chain mismatch.
  try {
    verifyChain(args.bundle.events);
    result.chainOk = true;
  } catch (e) {
    result.chainOk = false;
    result.reason = `event hash chain failed: ${(e as Error).message}`;
    return result;
  }

  // Anchors.
  if (args.verifyAnchor && args.bundle.anchors) {
    const bundleBytes = new TextEncoder().encode(canonicalize(args.bundle as unknown));
    for (const anchor of args.bundle.anchors) {
      const ok = await args.verifyAnchor(anchor, bundleBytes);
      result.anchors.push({ kind: anchor.kind, ok });
      if (!ok) {
        result.reason = `anchor ${anchor.kind} inclusion proof failed`;
        return result;
      }
    }
  }

  result.ok = true;
  return result;
}

/* -------------------------------------------------------------------------- */
/*  Replay / timeline                                                         */
/* -------------------------------------------------------------------------- */

export interface TimelineEntry {
  timestamp: Timestamp;
  actor: ActorId;
  type: string;
  level: ProofLevel;
  policy_rule_id?: string;
  approval?: { decision: "approve" | "deny"; responder: ActorId };
  ceremony_kind?: string;
  notes?: string;
}

/** Walk events / decisions / approvals in chronological order and
 *  produce a single flat timeline an audit dashboard can render. */
export function replayEvidence(bundle: EvidenceBundle): TimelineEntry[] {
  const entries: TimelineEntry[] = bundle.events.map((ev) => ({
    timestamp: ev.timestamp,
    actor: ev.actor_id,
    type: ev.type,
    level: ev.level,
  }));
  for (const d of bundle.policy_decisions) {
    entries.push({
      timestamp: d.evaluated_at,
      actor: d.subject,
      type: `policy.${d.decision}`,
      level: bundle.level ?? "L1",
      policy_rule_id: d.rule_id,
      notes: d.reason,
    });
  }
  for (const a of bundle.approvals) {
    const ceremony = bundle.ceremonies?.find((c) => c.request_id === a.request_id);
    entries.push({
      timestamp: a.signed_at,
      actor: a.responder,
      type: "approval",
      level: bundle.level ?? "L1",
      approval: { decision: a.decision, responder: a.responder },
      ceremony_kind: ceremony?.kind,
      notes: a.note,
    });
  }
  // Sort by parsed Date so events with mixed `Z` / `+00:00` ISO formats
  // interleave correctly. (Pre-B6 lexicographic sort put e.g.
  // "2026-04-25T10:00:00.500Z" AFTER "2026-04-25T10:00:01+00:00" because
  // the strings differed at the timezone position.)
  entries.sort((x, y) => {
    const dx = Date.parse(x.timestamp);
    const dy = Date.parse(y.timestamp);
    if (Number.isNaN(dx) || Number.isNaN(dy)) {
      return x.timestamp < y.timestamp ? -1 : x.timestamp > y.timestamp ? 1 : 0;
    }
    return dx - dy;
  });
  return entries;
}

/* -------------------------------------------------------------------------- */
/*  Redaction                                                                 */
/* -------------------------------------------------------------------------- */

export type RedactionPolicy =
  | { field: string; policy: "keep" }
  | { field: string; policy: "drop" }
  | { field: string; policy: "hash" };

/** Apply a redaction policy to every event's `context` field. The
 *  redacted bundle is signed afresh; callers must re-anchor if needed. */
export async function redactBundle(
  bundle: EvidenceBundle,
  policies: RedactionPolicy[],
  issuerPrivateKey: Uint8Array,
): Promise<EvidenceBundle> {
  const redactedEvents = bundle.events.map((ev) => {
    if (!ev.context) return ev;
    const ctx = { ...(ev.context as Record<string, unknown>) };
    for (const p of policies) {
      const segments = p.field.split(".");
      const last = segments.pop()!;
      let cursor: Record<string, unknown> = ctx;
      for (const s of segments) {
        if (!(s in cursor) || typeof cursor[s] !== "object" || cursor[s] === null) {
          cursor = {};
          break;
        }
        cursor = cursor[s] as Record<string, unknown>;
      }
      if (!(last in cursor)) continue;
      switch (p.policy) {
        case "keep":
          break;
        case "drop":
          delete cursor[last];
          break;
        case "hash":
          cursor[last] =
            "sha256:" +
            Buffer.from(sha256(new TextEncoder().encode(canonicalize(cursor[last] as unknown))))
              .toString("hex");
          break;
      }
    }
    return { ...ev, context: ctx };
  });
  const redacted: EvidenceBundle = {
    ...bundle,
    events: redactedEvents,
    signature: { algorithm: "ed25519", signer: bundle.issuer, signature: "" } as SignatureEnvelope,
  };
  const digest = evidenceBundleSigningBytes(redacted);
  const sig = await ed25519Sign(digest, issuerPrivateKey);
  redacted.signature = {
    algorithm: "ed25519",
    signer: bundle.issuer,
    signature: Buffer.from(sig).toString("base64"),
  };
  return redacted;
}
