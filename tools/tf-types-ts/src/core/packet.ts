/**
 * Packet mode (TF-0011): standalone signed/encrypted objects that can
 * be delivered offline, relayed, stored, transferred, or verified
 * later. Every packet carries a priority class, expiration, route
 * constraints, and an ed25519 signature; large packets fragment into
 * an indexed sequence with a payload digest so any reassembled output
 * can be byte-checked against the original.
 *
 * Wire encoding is JSON canonicalisation by default; CBOR is offered
 * as a compact alternative for LoRa / serial transports. Compression
 * is optional (deflate). Both must be honoured by signers and
 * verifiers; the `encoding` and `compression` fields tell the verifier
 * which decoders to apply.
 *
 * The reference CLI (`tools/tf-packet/`) provides
 * sign/verify/inspect/fragment/reassemble/simulate-lora.
 */

import { deflateSync, inflateSync } from "node:zlib";
import { encode as cborEncode, decode as cborDecode } from "./cbor.js";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify, sha256 } from "./crypto.js";
import { isWithinWindow } from "./expiration.js";

export type Priority = "P0" | "P1" | "P2" | "P3" | "P4" | "P5";
export type PacketEncoding = "json" | "cbor";
export type Compression = "none" | "deflate";

export interface PacketFragmentHeader {
  fragment_id: string;
  index: number;
  count: number;
  total_payload_bytes: number;
  payload_digest: string;
}

import type { Packet } from "../generated/packet.js";

// Note: `Packet` is re-exported from generated/index.js — we intentionally
// only `import type` it here so this module doesn't double-export it.
export type { Packet };

export interface SignPacketArgs {
  packetId: string;
  source: string;
  destination: string;
  priority: Priority;
  payload: Uint8Array;
  encoding?: PacketEncoding;
  compression?: Compression;
  emergency?: boolean;
  expiresAt?: string;
  ttlHops?: number;
  routeConstraints?: string[];
  sessionRef?: string;
  privateKey: Uint8Array;
  signer: string;
  createdAt?: string;
}

export function packetSigningBytes(p: Packet): Uint8Array {
  const { signature: _signature, ...rest } = p;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

export async function signPacket(args: SignPacketArgs): Promise<Packet> {
  if (args.priority === "P0" && !args.emergency) {
    throw new Error("P0 priority is reserved for emergency packets");
  }
  const encoding: PacketEncoding = args.encoding ?? "cbor";
  const compression: Compression = args.compression ?? "none";
  const payloadBytes =
    encoding === "cbor"
      ? new Uint8Array(cborEncode({ raw: args.payload }))
      : new TextEncoder().encode(canonicalize({ raw: Buffer.from(args.payload).toString("base64") }));
  const finalBytes =
    compression === "deflate" ? new Uint8Array(deflateSync(payloadBytes)) : payloadBytes;
  const draft: Packet = {
    packet_version: "1",
    packet_id: args.packetId,
    source: args.source,
    destination: args.destination,
    priority: args.priority,
    created_at: args.createdAt ?? new Date().toISOString(),
    encoding,
    compression,
    payload: Buffer.from(finalBytes).toString("base64"),
    signature: { algorithm: "ed25519", signer: args.signer, signature: "" },
  };
  if (args.emergency) draft.emergency = true;
  if (args.expiresAt) draft.expires_at = args.expiresAt;
  if (args.ttlHops !== undefined) draft.ttl_hops = args.ttlHops;
  if (args.routeConstraints && args.routeConstraints.length > 0)
    draft.route_constraints = args.routeConstraints;
  if (args.sessionRef) draft.session_ref = args.sessionRef;
  const digest = packetSigningBytes(draft);
  const sig = await ed25519Sign(digest, args.privateKey);
  draft.signature = {
    algorithm: "ed25519",
    signer: args.signer,
    signature: Buffer.from(sig).toString("base64"),
  };
  return draft;
}

export interface VerifyPacketResult {
  ok: boolean;
  reason?: string;
  payload?: Uint8Array;
}

export async function verifyPacket(
  packet: Packet,
  publicKey: Uint8Array,
  now: string = new Date().toISOString(),
): Promise<VerifyPacketResult> {
  if (packet.packet_version !== "1") {
    return { ok: false, reason: `unsupported packet_version ${packet.packet_version}` };
  }
  if (packet.signature.signer !== packet.source) {
    return { ok: false, reason: "signature signer does not match source" };
  }
  if (packet.priority === "P0" && !packet.emergency) {
    return { ok: false, reason: "P0 reserved for emergency packets" };
  }
  if (packet.expires_at && !isWithinWindow({ valid_until: packet.expires_at }, now)) {
    return { ok: false, reason: "packet expired" };
  }
  const digest = packetSigningBytes(packet);
  const sigBytes = new Uint8Array(Buffer.from(packet.signature.signature, "base64"));
  const ok = await ed25519Verify(publicKey, digest, sigBytes);
  if (!ok) return { ok: false, reason: "signature verification failed" };
  // Decode payload back to bytes.
  const wireBytes = new Uint8Array(Buffer.from(packet.payload, "base64"));
  const decompressed =
    packet.compression === "deflate" ? new Uint8Array(inflateSync(wireBytes)) : wireBytes;
  let payload: Uint8Array;
  try {
    if (packet.encoding === "cbor") {
      const obj = cborDecode(decompressed) as { raw: Uint8Array };
      payload = obj.raw instanceof Uint8Array ? obj.raw : new Uint8Array(obj.raw as ArrayLike<number>);
    } else {
      const obj = JSON.parse(new TextDecoder().decode(decompressed)) as { raw: string };
      payload = new Uint8Array(Buffer.from(obj.raw, "base64"));
    }
  } catch (e) {
    return { ok: false, reason: `payload decode failed: ${(e as Error).message}` };
  }
  return { ok: true, payload };
}

/* -------------------------------------------------------------------------- */
/*  Fragmentation / reassembly                                                */
/* -------------------------------------------------------------------------- */

export interface FragmentOptions {
  /** Maximum payload bytes per fragment (the rest of the packet adds
   *  ~256 bytes of metadata). Default 256 (LoRa-friendly). */
  mtu?: number;
}

export async function fragmentPacket(
  source: Packet,
  privateKey: Uint8Array,
  opts: FragmentOptions = {},
): Promise<Packet[]> {
  const mtu = opts.mtu ?? 256;
  const fragmentId = `frag-${source.packet_id}`;
  const original = new Uint8Array(Buffer.from(source.payload, "base64"));
  const totalBytes = original.length;
  const digest = "sha256:" + Buffer.from(sha256(original)).toString("hex");
  if (totalBytes <= mtu) {
    return [source];
  }
  const count = Math.ceil(totalBytes / mtu);
  const out: Packet[] = [];
  for (let i = 0; i < count; i++) {
    const slice = original.slice(i * mtu, Math.min((i + 1) * mtu, totalBytes));
    const fragment: PacketFragmentHeader = {
      fragment_id: fragmentId,
      index: i,
      count,
      total_payload_bytes: totalBytes,
      payload_digest: digest,
    };
    const draft: Packet = {
      packet_version: "1",
      packet_id: `${source.packet_id}-${i}`,
      source: source.source,
      destination: source.destination,
      priority: source.priority,
      created_at: source.created_at,
      payload: Buffer.from(slice).toString("base64"),
      fragment,
      signature: { algorithm: "ed25519", signer: source.source, signature: "" },
    };
    if (source.emergency) draft.emergency = true;
    if (source.expires_at) draft.expires_at = source.expires_at;
    if (source.ttl_hops !== undefined) draft.ttl_hops = source.ttl_hops;
    if (source.route_constraints) draft.route_constraints = source.route_constraints;
    if (source.session_ref) draft.session_ref = source.session_ref;
    if (source.encoding) draft.encoding = source.encoding;
    if (source.compression) draft.compression = source.compression;
    const fragDigest = packetSigningBytes(draft);
    const sig = await ed25519Sign(fragDigest, privateKey);
    draft.signature = {
      algorithm: "ed25519",
      signer: source.source,
      signature: Buffer.from(sig).toString("base64"),
    };
    out.push(draft);
  }
  return out;
}

export interface ReassembleResult {
  ok: boolean;
  reason?: string;
  packetId?: string;
  payload?: Uint8Array;
}

export function reassembleFragments(fragments: Packet[]): ReassembleResult {
  if (fragments.length === 0) return { ok: false, reason: "no fragments" };
  const first = fragments[0]!.fragment;
  if (!first) return { ok: false, reason: "first fragment missing fragment header" };
  const fragId = first.fragment_id;
  const count = first.count;
  if (fragments.length !== count) {
    return { ok: false, reason: `expected ${count} fragments, got ${fragments.length}` };
  }
  const ordered: (Packet | undefined)[] = new Array(count).fill(undefined);
  for (const f of fragments) {
    if (!f.fragment || f.fragment.fragment_id !== fragId) {
      return { ok: false, reason: "mismatched fragment_id" };
    }
    if (f.fragment.count !== count) {
      return { ok: false, reason: "mismatched fragment count" };
    }
    if (ordered[f.fragment.index] !== undefined) {
      return { ok: false, reason: `duplicate fragment index ${f.fragment.index}` };
    }
    ordered[f.fragment.index] = f;
  }
  if (ordered.some((p) => p === undefined)) {
    return { ok: false, reason: "missing one or more fragment indices" };
  }
  const total = first.total_payload_bytes;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const f of ordered as Packet[]) {
    const slice = new Uint8Array(Buffer.from(f.payload, "base64"));
    if (offset + slice.length > total) {
      return { ok: false, reason: "fragment overflows declared total bytes" };
    }
    out.set(slice, offset);
    offset += slice.length;
  }
  if (offset !== total) {
    return { ok: false, reason: `assembled ${offset} bytes, expected ${total}` };
  }
  const computed = "sha256:" + Buffer.from(sha256(out)).toString("hex");
  if (computed !== first.payload_digest) {
    return { ok: false, reason: "reassembled payload digest mismatch" };
  }
  return { ok: true, packetId: fragId, payload: out };
}

/* -------------------------------------------------------------------------- */
/*  LoRa-style transport simulator                                            */
/* -------------------------------------------------------------------------- */

export interface LoraSimOptions {
  /** Fraction of frames dropped, 0..1. Default 0. */
  packetLoss?: number;
  /** Bandwidth in bytes per second (used to model latency). Default 250 (SF7). */
  bandwidthBps?: number;
  /** Per-frame fixed latency in ms (RF + processing). Default 5000ms. */
  baseLatencyMs?: number;
  /** Optional seeded RNG for deterministic tests. */
  random?: () => number;
}

export interface SimulationResult {
  delivered: Packet[];
  dropped: Packet[];
  /** Cumulative simulated latency in ms. */
  totalLatencyMs: number;
}

/** Walk a list of packets through a one-way LoRa-style channel. Drops
 *  fragments per `packetLoss`, accumulates latency proportional to size
 *  divided by `bandwidthBps`. Pure simulation — no IO. */
export function simulateLora(packets: Packet[], opts: LoraSimOptions = {}): SimulationResult {
  const loss = opts.packetLoss ?? 0;
  const bw = opts.bandwidthBps ?? 250;
  const base = opts.baseLatencyMs ?? 5000;
  const rng = opts.random ?? Math.random;
  const delivered: Packet[] = [];
  const dropped: Packet[] = [];
  let totalLatencyMs = 0;
  for (const p of packets) {
    const sizeBytes = Buffer.from(canonicalize(p as unknown)).byteLength;
    const txMs = (sizeBytes / bw) * 1000;
    totalLatencyMs += base + txMs;
    if (rng() < loss) dropped.push(p);
    else delivered.push(p);
  }
  return { delivered, dropped, totalLatencyMs };
}

/* -------------------------------------------------------------------------- */
/*  Emergency authority + post-event quorum review                            */
/* -------------------------------------------------------------------------- */

export interface EmergencyInvocation {
  packet: Packet;
  /** The post-event quorum review that audits the emergency action.
   *  Required before evidence bundles can include the emergency event. */
  reviewBundleId?: string;
}

export function isEmergencyPacket(p: Packet): boolean {
  return p.priority === "P0" && p.emergency === true;
}

/** Build a packet bundle that pairs an emergency packet with its
 *  required post-event quorum review (TF-0011 \"emergency packets must
 *  be scoped, logged, and reviewable\"). */
export function emergencyReviewBundle(args: {
  bundleId: string;
  emergency: Packet;
  reviewPackets: Packet[];
  signer: string;
  privateKey: Uint8Array;
  transportHint?: "usb" | "qr-code" | "serial" | "lora" | "file-drop" | "manual";
  createdAt?: string;
}): Promise<{
  bundle_version: "1";
  bundle_id: string;
  label: string;
  packets: Packet[];
  transport_hint?: string;
  created_at: string;
  signature: { algorithm: string; signer: string; signature: string };
}> {
  if (!isEmergencyPacket(args.emergency)) {
    return Promise.reject(new Error("first packet must be a P0 emergency packet"));
  }
  if (args.reviewPackets.length === 0) {
    return Promise.reject(new Error("emergency review bundle requires at least one review packet"));
  }
  const draft = {
    bundle_version: "1" as const,
    bundle_id: args.bundleId,
    label: "emergency invocation + quorum review",
    packets: [args.emergency, ...args.reviewPackets],
    transport_hint: args.transportHint,
    created_at: args.createdAt ?? new Date().toISOString(),
    signature: {
      algorithm: "ed25519",
      signer: args.signer,
      signature: "",
    } as { algorithm: string; signer: string; signature: string },
  };
  const digest = sha256(
    new TextEncoder().encode(canonicalize({ ...draft, signature: undefined } as unknown)),
  );
  return ed25519Sign(digest, args.privateKey).then((sig) => {
    draft.signature.signature = Buffer.from(sig).toString("base64");
    return draft;
  });
}
