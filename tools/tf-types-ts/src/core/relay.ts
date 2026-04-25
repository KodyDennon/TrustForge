/**
 * Relay model — strict separation between forwarding authority and
 * action authority (TF-0003 / DECISIONS.md "Relay and mesh forwarding").
 *
 * A relay carries TrustForge frames between peers without ever being
 * able to decrypt, authorize, approve, or execute them. The
 * `RelayHandler` interface enforces this in the type system: it only
 * sees `RelayFrame` (encrypted opaque bytes + minimal routing metadata)
 * and emits a `RelayForwardedEvent` proof event for every forwarded
 * frame. The `ActionAuthority` interface — held only by endpoints —
 * decrypts and executes; relays never see it.
 *
 * The `RelayAuthority` record (relay-authority.schema.json) is the
 * grant a trust-domain authority issues to a relay. The default
 * `signRelayAuthority` / `verifyRelayAuthority` helpers handle the
 * ed25519 envelope; the runtime in this module enforces hop limits and
 * rate limits at forward time.
 */

import type { ActorId, SignatureEnvelope, Timestamp } from "../generated/_common.js";
import type { RelayAuthority } from "../generated/relay-authority.js";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify, sha256 } from "./crypto.js";
import { isWithinWindow } from "./expiration.js";

export interface RelayFrame {
  /** Opaque ciphertext blob. Relays MUST treat this as opaque. */
  ciphertext: Uint8Array;
  /** Final destination actor — used by the relay to route, never to
   *  decrypt or execute. */
  destination: ActorId;
  /** Per-frame priority class P0–P5 (TF-0011). */
  priority?: "P0" | "P1" | "P2" | "P3" | "P4" | "P5";
  /** Hop count incremented by each relay; the original sender starts
   *  at 0. */
  hop_count: number;
  /** Optional packet expiration; relays drop expired packets. */
  expires_at?: Timestamp;
  /** Optional source actor for audit. Not authoritative — endpoints
   *  re-verify the embedded signature inside the ciphertext. */
  source?: ActorId;
}

export interface RelayForwardedEvent {
  type: "relay.forwarded";
  relay: ActorId;
  destination: ActorId;
  source?: ActorId;
  hop_count_in: number;
  hop_count_out: number;
  size_bytes: number;
  forwarded_at: Timestamp;
  authority_id?: string;
  priority?: string;
}

export class RelayPolicyError extends Error {}

export interface RelayHandlerOptions {
  /** Bound RelayAuthority — the relay refuses to forward unless its
   *  authority validates against this record. */
  authority: RelayAuthority;
  /** ed25519 public key of the issuer; used to verify the authority. */
  issuerPublicKey: Uint8Array;
  /** Optional emit hook for proof events. */
  onForwarded?: (ev: RelayForwardedEvent) => void;
  /** Optional clock override for testing. */
  now?: () => Timestamp;
}

/** RelayHandler — forwarding-only role. The interface intentionally has
 *  NO decrypt / execute / approve methods so the type system prevents
 *  relay code from accidentally taking action authority. */
export class RelayHandler {
  private readonly authority: RelayAuthority;
  private readonly onForwarded?: (ev: RelayForwardedEvent) => void;
  private readonly now: () => Timestamp;
  private rateBucketStart = 0;
  private rateBucketCount = 0;
  private validatedAuthority = false;
  private issuerPub: Uint8Array;

  constructor(opts: RelayHandlerOptions) {
    this.authority = opts.authority;
    this.onForwarded = opts.onForwarded;
    this.now = opts.now ?? (() => new Date().toISOString());
    this.issuerPub = opts.issuerPublicKey;
  }

  /** Forward a frame onward. Throws RelayPolicyError if the bound
   *  authority is invalid, expired, exceeds hop count, or hits the
   *  configured rate limit. Returns the outgoing RelayFrame. */
  async forward(frame: RelayFrame): Promise<RelayFrame> {
    if (!this.validatedAuthority) {
      const v = await verifyRelayAuthority(this.authority, this.issuerPub);
      if (!v.ok) throw new RelayPolicyError(`relay authority invalid: ${v.reason}`);
      this.validatedAuthority = true;
    }
    const now = this.now();
    if (
      !isWithinWindow(
        { valid_from: this.authority.valid_from, valid_until: this.authority.valid_until },
        now,
      )
    ) {
      throw new RelayPolicyError("relay authority outside valid_from/valid_until");
    }
    if (frame.expires_at && frame.expires_at < now) {
      throw new RelayPolicyError("frame expired before forwarding");
    }
    if (this.authority.max_hop_count !== undefined && frame.hop_count >= this.authority.max_hop_count) {
      throw new RelayPolicyError(
        `hop count ${frame.hop_count} >= max ${this.authority.max_hop_count}`,
      );
    }
    if (this.authority.rate_limit_per_minute !== undefined) {
      const minute = Math.floor(Date.parse(now) / 60_000);
      if (minute !== this.rateBucketStart) {
        this.rateBucketStart = minute;
        this.rateBucketCount = 0;
      }
      this.rateBucketCount += 1;
      if (this.rateBucketCount > this.authority.rate_limit_per_minute) {
        throw new RelayPolicyError(
          `rate limit ${this.authority.rate_limit_per_minute}/min exceeded`,
        );
      }
    }

    const outgoing: RelayFrame = {
      ...frame,
      hop_count: frame.hop_count + 1,
    };
    this.onForwarded?.({
      type: "relay.forwarded",
      relay: this.authority.relay,
      destination: frame.destination,
      source: frame.source,
      hop_count_in: frame.hop_count,
      hop_count_out: outgoing.hop_count,
      size_bytes: frame.ciphertext.length,
      forwarded_at: now,
      authority_id: this.authority.relay,
      priority: frame.priority,
    });
    return outgoing;
  }

  /** Read-only view of the bound authority. */
  authorityRecord(): RelayAuthority {
    return this.authority;
  }
}

/** Action authority — the role endpoints hold. Relays NEVER hold this. */
export interface ActionAuthority {
  /** Decrypt and authenticate the payload. */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
  /** Run the decoded action subject to the daemon's policy. */
  execute(decoded: Uint8Array): Promise<unknown>;
}

/* -------------------------------------------------------------------------- */
/*  Relay authority signing / verifying                                       */
/* -------------------------------------------------------------------------- */

export function relayAuthoritySigningBytes(a: RelayAuthority): Uint8Array {
  const { signature: _signature, ...rest } = a;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

export interface SignRelayAuthorityArgs {
  authority: Omit<RelayAuthority, "signature">;
  privateKey: Uint8Array;
  signer: ActorId;
}

export async function signRelayAuthority(args: SignRelayAuthorityArgs): Promise<RelayAuthority> {
  const draft: RelayAuthority = {
    ...args.authority,
    signature: { algorithm: "ed25519", signer: args.signer, signature: "" } as SignatureEnvelope,
  };
  const digest = relayAuthoritySigningBytes(draft);
  const sig = await ed25519Sign(digest, args.privateKey);
  draft.signature = {
    algorithm: "ed25519",
    signer: args.signer,
    signature: Buffer.from(sig).toString("base64"),
  };
  return draft;
}

export async function verifyRelayAuthority(
  authority: RelayAuthority,
  issuerPublicKey: Uint8Array,
): Promise<{ ok: boolean; reason?: string }> {
  if (authority.relay_authority_version !== "1") {
    return { ok: false, reason: `unsupported version ${authority.relay_authority_version}` };
  }
  if (authority.signature.algorithm !== "ed25519") {
    return { ok: false, reason: `unsupported signature algorithm ${authority.signature.algorithm}` };
  }
  if (authority.signature.signer !== authority.issuer) {
    return { ok: false, reason: "signature signer does not match authority issuer" };
  }
  const digest = relayAuthoritySigningBytes(authority);
  const sigBytes = new Uint8Array(Buffer.from(authority.signature.signature, "base64"));
  const ok = await ed25519Verify(issuerPublicKey, digest, sigBytes);
  if (!ok) return { ok: false, reason: "relay authority signature did not verify" };
  return { ok: true };
}
