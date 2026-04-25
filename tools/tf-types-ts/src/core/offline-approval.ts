/**
 * Offline-signed approval packets.
 *
 * The packet encodes a canonical ApprovalRequest, the responder's
 * decision, and an ed25519 signature so an air-gapped human can
 * approve a high-risk action without ever connecting to the daemon.
 * The daemon validates the packet, projects it to a normal
 * `ApprovalResponse + approval-ceremony` pair, and feeds it into the
 * queue.
 *
 * Wire format (CBOR-friendly, but we ship JSON for v0.1.0; the packet
 * mode in Sprint 4 swaps the encoder to compact CBOR while keeping the
 * canonicalized payload bytes byte-identical):
 *   {
 *     packet_version: "1",
 *     request: ApprovalRequest,        // canonicalized
 *     decision: "approve" | "deny",
 *     responder: ActorId,
 *     responded_at: Timestamp,
 *     transport_hint: "usb"|"qr-code"|"serial"|"lora"|"file-drop"|"manual",
 *     signature: SignatureEnvelope     // ed25519 over canonical request
 *   }
 */

import type { ActorId, Timestamp, SignatureEnvelope } from "../generated/_common.js";
import type { ApprovalRequest } from "../generated/approval-request.js";
import type { ApprovalResponse } from "../generated/approval-response.js";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify } from "./crypto.js";
import { sha256 } from "@noble/hashes/sha256";

export type OfflineTransportHint =
  | "usb"
  | "qr-code"
  | "serial"
  | "lora"
  | "file-drop"
  | "manual";

export interface OfflineApprovalPacket {
  packet_version: "1";
  request: ApprovalRequest;
  decision: "approve" | "deny";
  responder: ActorId;
  responded_at: Timestamp;
  transport_hint: OfflineTransportHint;
  /** Per-packet nonce — base64 of 16 random bytes. Used by the verifier
   *  to reject replays of an already-consumed packet. */
  nonce: string;
  signature: SignatureEnvelope;
}

export interface SignOfflineApprovalArgs {
  request: ApprovalRequest;
  decision: "approve" | "deny";
  responder: ActorId;
  /** Ed25519 32-byte private key. */
  privateKey: Uint8Array;
  /** Optional Ed25519 32-byte public key (for self-check). */
  publicKey?: Uint8Array;
  transportHint: OfflineTransportHint;
  respondedAt?: Timestamp;
  note?: string;
}

/** Sign an offline approval packet. The signature is over
 *  sha256(canonicalize({request, decision, responder, responded_at}))
 *  so verification is replayable without re-canonicalizing. */
export async function signOfflineApprovalPacket(
  args: SignOfflineApprovalArgs,
): Promise<OfflineApprovalPacket> {
  const respondedAt = args.respondedAt ?? new Date().toISOString();
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = Buffer.from(nonceBytes).toString("base64");
  // The signature now covers transport_hint + nonce so a relay can't
  // rewrite either without invalidating the signature.
  const payload = {
    request: args.request,
    decision: args.decision,
    responder: args.responder,
    responded_at: respondedAt,
    transport_hint: args.transportHint,
    nonce,
  };
  const digest = sha256(new TextEncoder().encode(canonicalize(payload as unknown)));
  const sig = await ed25519Sign(digest, args.privateKey);
  return {
    packet_version: "1",
    request: args.request,
    decision: args.decision,
    responder: args.responder,
    responded_at: respondedAt,
    transport_hint: args.transportHint,
    nonce,
    signature: {
      algorithm: "ed25519",
      signer: args.responder,
      signature: Buffer.from(sig).toString("base64"),
    },
  };
}

export interface VerifyOfflineApprovalArgs {
  packet: OfflineApprovalPacket;
  /** Ed25519 32-byte public key the responder published. */
  publicKey: Uint8Array;
  /** Optional clock for replay checks. */
  now?: Timestamp;
  /** Reject packets older than this many seconds (default 86400). */
  maxAgeSeconds?: number;
  /** Verifier-supplied set of (responder, request_id, nonce) triples
   *  already consumed. The verifier returns an error if the packet
   *  was previously seen — and the caller MUST add the new packet's
   *  triple before calling again. Pre-B6 the verifier had no replay
   *  defence; an attacker could re-feed the same signed packet to
   *  drive any number of approvals. */
  isConsumed?: (key: { responder: ActorId; request_id: string; nonce: string }) => boolean;
}

export interface VerifyOfflineApprovalResult {
  ok: boolean;
  reason?: string;
  response?: ApprovalResponse;
  ceremony?: {
    ceremony_version: "1";
    ceremony_id: string;
    kind: "offline-signed-packet";
    request_id: string;
    responder: ActorId;
    packet_id: string;
    transport_hint: OfflineTransportHint;
    signature: string;
  };
}

/** Verify the packet's signature, age, and structure; return a normal
 *  ApprovalResponse + ceremony record on success. */
export async function verifyOfflineApprovalPacket(
  args: VerifyOfflineApprovalArgs,
): Promise<VerifyOfflineApprovalResult> {
  const p = args.packet;
  if (p.packet_version !== "1") {
    return { ok: false, reason: `unsupported packet_version ${p.packet_version}` };
  }
  if (p.signature.signer !== p.responder) {
    return { ok: false, reason: "signature signer does not match responder" };
  }
  if (p.signature.algorithm !== "ed25519") {
    return { ok: false, reason: `unsupported signature algorithm ${p.signature.algorithm}` };
  }
  const now = args.now ?? new Date().toISOString();
  const max = args.maxAgeSeconds ?? 86_400;
  const ageMs = Date.parse(now) - Date.parse(p.responded_at);
  if (Number.isFinite(ageMs)) {
    if (ageMs / 1000 > max) {
      return { ok: false, reason: `packet older than ${max}s` };
    }
    if (ageMs < -300_000) {
      return { ok: false, reason: "packet timestamp is in the future" };
    }
  }
  if (typeof p.nonce !== "string" || p.nonce.length === 0) {
    return { ok: false, reason: "missing nonce" };
  }
  if (args.isConsumed) {
    const seen = args.isConsumed({
      responder: p.responder,
      request_id: p.request.id,
      nonce: p.nonce,
    });
    if (seen) {
      return { ok: false, reason: "packet has already been consumed (replay)" };
    }
  }
  const payload = {
    request: p.request,
    decision: p.decision,
    responder: p.responder,
    responded_at: p.responded_at,
    transport_hint: p.transport_hint,
    nonce: p.nonce,
  };
  const digest = sha256(new TextEncoder().encode(canonicalize(payload as unknown)));
  const sigBytes = new Uint8Array(Buffer.from(p.signature.signature, "base64"));
  const ok = await ed25519Verify(args.publicKey, digest, sigBytes);
  if (!ok) return { ok: false, reason: "signature verification failed" };
  const packetId = `pkt-${Buffer.from(digest).toString("hex").slice(0, 16)}`;
  const response: ApprovalResponse = {
    response_version: "1",
    request_id: p.request.id,
    decision: p.decision,
    responder: p.responder,
    signed_at: p.responded_at,
    signature: p.signature,
  };
  const ceremony = {
    ceremony_version: "1" as const,
    ceremony_id: `cer-${packetId}`,
    kind: "offline-signed-packet" as const,
    request_id: p.request.id,
    responder: p.responder,
    packet_id: packetId,
    transport_hint: p.transport_hint,
    signature: p.signature.signature,
  };
  return { ok: true, response, ceremony };
}
