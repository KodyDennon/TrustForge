/**
 * Constrained-mode runtime primitives — TF-0011.
 *
 * Constrained deployments (LoRa mesh, air-gapped relays, USB-shuttle,
 * intermittent satellites) need anti-replay protection on the
 * receiver, a way to honour offline revocations without phoning home,
 * delivery receipts so packets sent over a one-way bearer can prove
 * they arrived, and proof-of-forwarding receipts so a relay can show
 * it actually carried a packet without seeing its plaintext.
 *
 * The Rust mirror lives at `crates/tf-types/src/constrained.rs`.
 */

import { ed25519Sign, ed25519Verify, sha256HashRef, toHex } from "./crypto.js";
import { canonicalize } from "./canonical.js";
import type { Packet } from "../generated/packet.js";
import type {
  OfflineRevocationList,
  RevokedEntry,
} from "../generated/offline-revocation-list.js";
import type { ActorId, Timestamp, SignatureEnvelope } from "../generated/_common.js";

/* -------------------------------------------------------------------------- */
/*  PacketReceiver — sliding-window nonce cache                               */
/* -------------------------------------------------------------------------- */

export interface PacketReceiverOptions {
  /** Maximum number of recently-seen packet_ids to remember. Older ids
   *  age out as new ones arrive (LRU). Default 4096; constrained
   *  receivers should pick a value sized to their RAM budget. */
  windowSize?: number;
  /** Optional clock; used by `expireOlderThan` for window pruning. */
  now?: () => string;
}

export type PacketReceiverDecision =
  | { kind: "accept" }
  | { kind: "reject"; reason: "replay" | "expired" | "future-dated" };

/**
 * Sliding-window nonce cache for packet-mode anti-replay. Receivers
 * record `(packet_id, expires_at)` for each accepted packet and reject
 * any subsequent packet whose `packet_id` is already in the window.
 *
 * The window evicts entries on capacity overflow and supports
 * deliberate pruning of expired entries via `expireOlderThan`.
 */
export class PacketReceiver {
  private readonly seen = new Map<string, string>(); // packet_id -> expires_at
  private readonly windowSize: number;
  private readonly now: () => string;

  constructor(opts: PacketReceiverOptions = {}) {
    this.windowSize = opts.windowSize ?? 4096;
    this.now = opts.now ?? (() => new Date().toISOString());
  }

  /** Check + record a packet. Pure decision; if you call this twice
   *  with the same packet, the second call returns `replay`. */
  observe(packet: Packet): PacketReceiverDecision {
    const now = this.now();
    if (packet.expires_at && packet.expires_at < now) {
      return { kind: "reject", reason: "expired" };
    }
    if (packet.created_at && packet.created_at > now) {
      // Tolerate up to a few minutes of clock skew? — strict check
      // here, a future-dated packet that survives the receiver's clock
      // drift signals tampering.
      return { kind: "reject", reason: "future-dated" };
    }
    if (this.seen.has(packet.packet_id)) {
      return { kind: "reject", reason: "replay" };
    }
    if (this.seen.size >= this.windowSize) {
      // Map preserves insertion order; evict the oldest entry.
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.set(packet.packet_id, packet.expires_at ?? "");
    return { kind: "accept" };
  }

  /** Drop entries whose recorded `expires_at` is `< before`. Useful at
   *  start-of-tick on a receiver that wants the window to follow real
   *  time rather than just LRU. */
  expireOlderThan(before: string): number {
    let removed = 0;
    for (const [id, exp] of this.seen) {
      if (exp && exp < before) {
        this.seen.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  size(): number {
    return this.seen.size;
  }
}

/* -------------------------------------------------------------------------- */
/*  OfflineRevocationListRuntime — sealed-list verifier                       */
/* -------------------------------------------------------------------------- */

export class OfflineRevocationListRuntime {
  private readonly list: OfflineRevocationList;
  private readonly index = new Map<string, RevokedEntry>(); // `${kind}:${id}` → entry

  private constructor(list: OfflineRevocationList) {
    this.list = list;
    for (const e of list.revoked) {
      this.index.set(`${e.kind}:${e.id}`, e);
    }
  }

  /** Build the runtime AFTER verifying the issuer signature. Refuses
   *  to construct if the signature does not validate, the list has
   *  expired (`valid_until` < now), or the list version is unknown. */
  static async load(
    list: OfflineRevocationList,
    args: {
      issuerPublicKey: Uint8Array;
      now: string;
    },
  ): Promise<OfflineRevocationListRuntime> {
    if (list.list_version !== "1") {
      throw new Error(`offline revocation list version ${list.list_version} unsupported`);
    }
    if (list.valid_until < args.now) {
      throw new Error(`offline revocation list expired at ${list.valid_until}`);
    }
    if (list.issued_at > args.now) {
      throw new Error(`offline revocation list dated in the future: ${list.issued_at}`);
    }
    const ok = await verifyOfflineRevocationListSignature(list, args.issuerPublicKey);
    if (!ok) throw new Error("offline revocation list signature did not verify");
    return new OfflineRevocationListRuntime(list);
  }

  /** Was a target revoked by this list? */
  isRevoked(target: { kind: RevokedEntry["kind"]; id: string }): RevokedEntry | undefined {
    return this.index.get(`${target.kind}:${target.id}`);
  }

  /** Issuer + window the list covers. */
  metadata(): { issuer: ActorId; trust_domain: string; issued_at: Timestamp; valid_until: Timestamp } {
    return {
      issuer: this.list.issuer,
      trust_domain: this.list.trust_domain,
      issued_at: this.list.issued_at,
      valid_until: this.list.valid_until,
    };
  }
}

export async function verifyOfflineRevocationListSignature(
  list: OfflineRevocationList,
  publicKey: Uint8Array,
): Promise<boolean> {
  const { signature, ...unsigned } = list;
  const canonical = canonicalize(unsigned);
  const sig = base64ToBytes(signature.signature);
  return ed25519Verify(publicKey, new TextEncoder().encode(canonical), sig);
}

/** Sign a draft `OfflineRevocationList`, attaching the issuer's
 *  signature in-place and returning the signed list. */
export async function signOfflineRevocationList(args: {
  list: Omit<OfflineRevocationList, "signature">;
  privateKey: Uint8Array;
  signer: ActorId;
}): Promise<OfflineRevocationList> {
  const draft = { ...args.list };
  const canonical = canonicalize(draft);
  const sig = await ed25519Sign(new TextEncoder().encode(canonical), args.privateKey);
  const signature: SignatureEnvelope = {
    algorithm: "ed25519",
    signer: args.signer,
    signature: bytesToBase64(sig),
  };
  return { ...draft, signature };
}

/* -------------------------------------------------------------------------- */
/*  Delivery receipts                                                         */
/* -------------------------------------------------------------------------- */

export interface DeliveryReceipt {
  receipt_version: "1";
  packet_id: string;
  /** sha256 hash-ref of the verified packet payload, so the receipt is
   *  bound to the actual bytes the receiver saw. */
  packet_hash: string;
  receiver: ActorId;
  received_at: Timestamp;
  signature: SignatureEnvelope;
}

/** Build a signed delivery receipt for an accepted packet. */
export async function signDeliveryReceipt(args: {
  packet: Packet;
  receiver: ActorId;
  receivedAt?: Timestamp;
  privateKey: Uint8Array;
}): Promise<DeliveryReceipt> {
  const canonical = canonicalize(args.packet);
  const packet_hash = sha256HashRef(new TextEncoder().encode(canonical));
  const draft: Omit<DeliveryReceipt, "signature"> = {
    receipt_version: "1",
    packet_id: args.packet.packet_id,
    packet_hash,
    receiver: args.receiver,
    received_at: args.receivedAt ?? new Date().toISOString(),
  };
  const sigCanonical = canonicalize(draft);
  const sig = await ed25519Sign(
    new TextEncoder().encode(sigCanonical),
    args.privateKey,
  );
  return {
    ...draft,
    signature: {
      algorithm: "ed25519",
      signer: args.receiver,
      signature: bytesToBase64(sig),
    },
  };
}

/** Verify a delivery receipt against the bytes of the packet the
 *  sender originally signed. */
export async function verifyDeliveryReceipt(
  receipt: DeliveryReceipt,
  packet: Packet,
  receiverPublicKey: Uint8Array,
): Promise<{ ok: boolean; reason?: string }> {
  if (receipt.receipt_version !== "1") {
    return { ok: false, reason: `receipt_version ${receipt.receipt_version} unsupported` };
  }
  if (receipt.packet_id !== packet.packet_id) {
    return { ok: false, reason: "packet_id mismatch" };
  }
  const canonical = canonicalize(packet);
  const expected = sha256HashRef(new TextEncoder().encode(canonical));
  if (expected !== receipt.packet_hash) {
    return { ok: false, reason: "packet_hash mismatch" };
  }
  if (receipt.signature.signer !== receipt.receiver) {
    return { ok: false, reason: "receipt signer != receiver" };
  }
  const { signature: _sig, ...unsigned } = receipt;
  const sigCanonical = canonicalize(unsigned);
  const sig = base64ToBytes(receipt.signature.signature);
  const ok = await ed25519Verify(
    receiverPublicKey,
    new TextEncoder().encode(sigCanonical),
    sig,
  );
  return ok
    ? { ok: true }
    : { ok: false, reason: "receipt signature did not verify" };
}

/* -------------------------------------------------------------------------- */
/*  Proof of forwarding                                                       */
/* -------------------------------------------------------------------------- */

export interface ProofOfForwarding {
  proof_version: "1";
  packet_id: string;
  packet_hash: string;
  relay: ActorId;
  forwarded_at: Timestamp;
  hop_count: number;
  signature: SignatureEnvelope;
}

/** Sign a proof-of-forwarding asserting that `relay` carried the
 *  packet at `forwarded_at` without claiming to have decrypted or
 *  authorised its payload. */
export async function signProofOfForwarding(args: {
  packet: Packet;
  relay: ActorId;
  forwardedAt?: Timestamp;
  hopCount: number;
  privateKey: Uint8Array;
}): Promise<ProofOfForwarding> {
  const canonical = canonicalize(args.packet);
  const packet_hash = sha256HashRef(new TextEncoder().encode(canonical));
  const draft: Omit<ProofOfForwarding, "signature"> = {
    proof_version: "1",
    packet_id: args.packet.packet_id,
    packet_hash,
    relay: args.relay,
    forwarded_at: args.forwardedAt ?? new Date().toISOString(),
    hop_count: args.hopCount,
  };
  const sigCanonical = canonicalize(draft);
  const sig = await ed25519Sign(
    new TextEncoder().encode(sigCanonical),
    args.privateKey,
  );
  return {
    ...draft,
    signature: {
      algorithm: "ed25519",
      signer: args.relay,
      signature: bytesToBase64(sig),
    },
  };
}

export async function verifyProofOfForwarding(
  proof: ProofOfForwarding,
  packet: Packet,
  relayPublicKey: Uint8Array,
): Promise<{ ok: boolean; reason?: string }> {
  if (proof.proof_version !== "1") {
    return { ok: false, reason: `proof_version ${proof.proof_version} unsupported` };
  }
  if (proof.packet_id !== packet.packet_id) {
    return { ok: false, reason: "packet_id mismatch" };
  }
  const canonical = canonicalize(packet);
  const expected = sha256HashRef(new TextEncoder().encode(canonical));
  if (expected !== proof.packet_hash) {
    return { ok: false, reason: "packet_hash mismatch" };
  }
  if (proof.signature.signer !== proof.relay) {
    return { ok: false, reason: "proof signer != relay" };
  }
  const { signature: _sig, ...unsigned } = proof;
  const sigCanonical = canonicalize(unsigned);
  const sig = base64ToBytes(proof.signature.signature);
  const ok = await ed25519Verify(
    relayPublicKey,
    new TextEncoder().encode(sigCanonical),
    sig,
  );
  return ok ? { ok: true } : { ok: false, reason: "forwarding signature did not verify" };
}

/* -------------------------------------------------------------------------- */
/*  helpers                                                                   */
/* -------------------------------------------------------------------------- */

function bytesToBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

function base64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

// Keep `toHex` re-exported for callers that want the digest hex form.
export { toHex };
