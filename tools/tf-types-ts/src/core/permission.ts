/**
 * Dynamic permission negotiation helpers.
 *
 * Agents call `signPermissionRequest` to mint a request, the daemon runs
 * its policy engine + approval queue, and replies with a grant minted by
 * `signPermissionGrant`. `verifyPermissionGrant` validates the grant's
 * ed25519 signature, expiry, and decision.
 */

import type { ActorId, SignatureEnvelope, Timestamp } from "../generated/_common.js";
import type { PermissionRequest } from "../generated/permission-request.js";
import type { PermissionGrant } from "../generated/permission-grant.js";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify } from "./crypto.js";
import { sha256 } from "@noble/hashes/sha256";
import { isWithinWindow } from "./expiration.js";

/** Produce the bytes the daemon signs over: SHA-256 of the canonical
 *  grant with the `signature` field omitted. */
export function permissionGrantSigningBytes(grant: PermissionGrant): Uint8Array {
  const { signature: _signature, ...rest } = grant;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

export interface SignPermissionGrantArgs {
  request: PermissionRequest;
  decision: PermissionGrant["decision"];
  issuer: ActorId;
  privateKey: Uint8Array;
  capability?: PermissionGrant["capability"];
  constraints?: PermissionGrant["constraints"];
  policyDecision?: PermissionGrant["policy_decision"];
  ceremonyId?: string;
  denialReason?: string;
  issuedAt?: Timestamp;
  validFrom?: Timestamp;
  validUntil?: Timestamp;
}

export async function signPermissionGrant(args: SignPermissionGrantArgs): Promise<PermissionGrant> {
  const issuedAt = args.issuedAt ?? new Date().toISOString();
  const grant: PermissionGrant = {
    grant_version: "1",
    request_id: args.request.id,
    decision: args.decision,
    issued_at: issuedAt,
    issuer: args.issuer,
    signature: { algorithm: "ed25519", signer: args.issuer, signature: "" },
  };
  if (args.capability) grant.capability = args.capability;
  if (args.constraints && args.constraints.length > 0) grant.constraints = args.constraints;
  if (args.policyDecision) grant.policy_decision = args.policyDecision;
  if (args.ceremonyId) grant.ceremony_id = args.ceremonyId;
  if (args.denialReason) grant.denial_reason = args.denialReason;
  if (args.validFrom) grant.valid_from = args.validFrom;
  if (args.validUntil) grant.valid_until = args.validUntil;

  const digest = permissionGrantSigningBytes(grant);
  const sig = await ed25519Sign(digest, args.privateKey);
  grant.signature = {
    algorithm: "ed25519",
    signer: args.issuer,
    signature: Buffer.from(sig).toString("base64"),
  };
  return grant;
}

export interface VerifyPermissionGrantArgs {
  grant: PermissionGrant;
  publicKey: Uint8Array;
  request?: PermissionRequest;
  now?: Timestamp;
}

export interface VerifyPermissionGrantResult {
  ok: boolean;
  reason?: string;
}

export async function verifyPermissionGrant(
  args: VerifyPermissionGrantArgs,
): Promise<VerifyPermissionGrantResult> {
  const g = args.grant;
  if (g.grant_version !== "1") {
    return { ok: false, reason: `unsupported grant_version ${g.grant_version}` };
  }
  if (g.signature.signer !== g.issuer) {
    return { ok: false, reason: "signature signer does not match issuer" };
  }
  if (g.signature.algorithm !== "ed25519") {
    return { ok: false, reason: `unsupported signature algorithm ${g.signature.algorithm}` };
  }
  if (args.request && g.request_id !== args.request.id) {
    return { ok: false, reason: "grant.request_id does not match request.id" };
  }
  const now = args.now ?? new Date().toISOString();
  const within = isWithinWindow(
    {
      valid_from: g.valid_from,
      valid_until: g.valid_until,
    },
    now,
  );
  if (!within) {
    return { ok: false, reason: "grant outside valid_from/valid_until window" };
  }
  const digest = permissionGrantSigningBytes(g);
  const sigBytes = new Uint8Array(Buffer.from(g.signature.signature, "base64"));
  const verified = await ed25519Verify(args.publicKey, digest, sigBytes);
  if (!verified) {
    return { ok: false, reason: "grant signature did not verify" };
  }
  return { ok: true };
}

/** Build a fresh PermissionRequest with sensible defaults. The agent
 *  may extend it with extra context fields before sending. */
export function makePermissionRequest(args: {
  id: string;
  agent: ActorId;
  action: string;
  reason: string;
  human?: ActorId;
  instance?: string;
  model?: string;
  tool?: string;
  target?: string;
  risk?: PermissionRequest["risk"];
  dangerTags?: PermissionRequest["danger_tags"];
  durationSeconds?: number;
  proofLevelOffered?: PermissionRequest["proof_level_offered"];
  requestedAt?: Timestamp;
  context?: Record<string, unknown>;
}): PermissionRequest {
  const r: PermissionRequest = {
    request_version: "1",
    id: args.id,
    agent: args.agent,
    action: args.action,
    reason: args.reason,
    requested_at: args.requestedAt ?? new Date().toISOString(),
  };
  if (args.human) r.human = args.human;
  if (args.instance) r.instance = args.instance;
  if (args.model) r.model = args.model;
  if (args.tool) r.tool = args.tool;
  if (args.target) r.target = args.target;
  if (args.risk) r.risk = args.risk;
  if (args.dangerTags && args.dangerTags.length > 0) r.danger_tags = args.dangerTags;
  if (args.durationSeconds) r.duration_seconds = args.durationSeconds;
  if (args.proofLevelOffered) r.proof_level_offered = args.proofLevelOffered;
  if (args.context && Object.keys(args.context).length > 0) r.context = args.context;
  return r;
}

/** Project a permission request onto a ProofEvent.provenance object so
 *  the audit log carries the human → agent → instance → model → tool
 *  chain DECISIONS.md calls for. */
export function provenanceFromRequest(req: PermissionRequest): {
  human?: ActorId;
  agent?: ActorId;
  instance?: string;
  model?: string;
  tool?: string;
  requested_action?: string;
} {
  const p: Record<string, unknown> = { agent: req.agent, requested_action: req.action };
  if (req.human) p.human = req.human;
  if (req.instance) p.instance = req.instance;
  if (req.model) p.model = req.model;
  if (req.tool) p.tool = req.tool;
  return p as ReturnType<typeof provenanceFromRequest>;
}

export type { SignatureEnvelope };
