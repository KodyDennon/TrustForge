/**
 * Binary container formats for TrustForge.
 *
 *   .tfbundle  — sealed/serialized proof bundle, L4/L5 capable.
 *      magic     = "TFBND" 0x01 0x00 0x00            (8 bytes)
 *      body_len  = u32 BE
 *      body      = CBOR-encoded ProofBundleEncrypted | ProofBundle
 *      sig_len   = u32 BE   (0 when unsigned)
 *      signature = sig_len bytes (raw ed25519)
 *
 *   .tfpkt     — packet-on-the-wire envelope.
 *      magic     = "TFPKT" 0x01 0x00 0x00            (8 bytes)
 *      body_len  = u32 BE
 *      body      = CBOR-encoded Packet
 *
 * CBOR (RFC 8949) is used for the body so the format is
 * binary-efficient on constrained transports (LoRa, USB shuttle, mesh)
 * while remaining round-trippable via every mainstream CBOR
 * implementation. The Rust mirror lives at
 * `crates/tf-types/src/binary_format.rs` and emits byte-identical
 * output for the same input — verified by
 * `conformance/binary-format-vectors.yaml`.
 */

import { encode as cborEncode, decode as cborDecode } from "cbor-x";
import type { Packet } from "../generated/packet.js";
import type { ProofBundle } from "../generated/proof-bundle.js";
import type { ProofBundleEncrypted } from "../generated/proof-bundle-encrypted.js";

export const TFBUNDLE_MAGIC = new Uint8Array([
  0x54, 0x46, 0x42, 0x4e, 0x44, 0x01, 0x00, 0x00,
]);
export const TFPKT_MAGIC = new Uint8Array([
  0x54, 0x46, 0x50, 0x4b, 0x54, 0x01, 0x00, 0x00,
]);

export class BinaryFormatError extends Error {}

function putU32BE(view: number[], n: number): void {
  if (n < 0 || n > 0xffffffff) {
    throw new BinaryFormatError(`length out of range: ${n}`);
  }
  view.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function readU32BE(buf: Uint8Array, off: number): number {
  if (off + 4 > buf.length) {
    throw new BinaryFormatError(`truncated at offset ${off}`);
  }
  return (
    ((buf[off]! << 24) |
      (buf[off + 1]! << 16) |
      (buf[off + 2]! << 8) |
      buf[off + 3]!) >>>
    0
  );
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  .tfbundle                                                                  */
/* -------------------------------------------------------------------------- */

export type TfbundleBody = ProofBundle | ProofBundleEncrypted;

export interface TfbundleParts {
  body: TfbundleBody;
  signature: Uint8Array;
  bodyBytes: Uint8Array;
}

export function writeTfbundle(body: TfbundleBody, signature?: Uint8Array): Uint8Array {
  const cbor = cborEncode(body);
  const bodyBytes = cbor instanceof Uint8Array ? cbor : new Uint8Array(cbor);
  const len1: number[] = [];
  putU32BE(len1, bodyBytes.length);
  const sig = signature ?? new Uint8Array(0);
  const len2: number[] = [];
  putU32BE(len2, sig.length);
  return concat([
    TFBUNDLE_MAGIC,
    new Uint8Array(len1),
    bodyBytes,
    new Uint8Array(len2),
    sig,
  ]);
}

export function readTfbundle(buf: Uint8Array): TfbundleParts {
  if (buf.length < TFBUNDLE_MAGIC.length) {
    throw new BinaryFormatError("truncated magic");
  }
  for (let i = 0; i < TFBUNDLE_MAGIC.length; i++) {
    if (buf[i] !== TFBUNDLE_MAGIC[i]) {
      throw new BinaryFormatError("bad .tfbundle magic");
    }
  }
  let off = TFBUNDLE_MAGIC.length;
  const bodyLen = readU32BE(buf, off);
  off += 4;
  if (off + bodyLen > buf.length) {
    throw new BinaryFormatError("truncated body");
  }
  const bodyBytes = buf.slice(off, off + bodyLen);
  const body = cborDecode(bodyBytes) as TfbundleBody;
  off += bodyLen;
  const sigLen = readU32BE(buf, off);
  off += 4;
  if (off + sigLen > buf.length) {
    throw new BinaryFormatError("truncated signature");
  }
  const signature = buf.slice(off, off + sigLen);
  return { body, signature, bodyBytes };
}

/* -------------------------------------------------------------------------- */
/*  .tfpkt                                                                     */
/* -------------------------------------------------------------------------- */

export interface TfpktParts {
  packet: Packet;
  bodyBytes: Uint8Array;
}

export function writeTfpkt(packet: Packet): Uint8Array {
  const cbor = cborEncode(packet);
  const bodyBytes = cbor instanceof Uint8Array ? cbor : new Uint8Array(cbor);
  const len: number[] = [];
  putU32BE(len, bodyBytes.length);
  return concat([TFPKT_MAGIC, new Uint8Array(len), bodyBytes]);
}

export function readTfpkt(buf: Uint8Array): TfpktParts {
  if (buf.length < TFPKT_MAGIC.length) {
    throw new BinaryFormatError("truncated magic");
  }
  for (let i = 0; i < TFPKT_MAGIC.length; i++) {
    if (buf[i] !== TFPKT_MAGIC[i]) {
      throw new BinaryFormatError("bad .tfpkt magic");
    }
  }
  let off = TFPKT_MAGIC.length;
  const bodyLen = readU32BE(buf, off);
  off += 4;
  if (off + bodyLen > buf.length) {
    throw new BinaryFormatError("truncated body");
  }
  const bodyBytes = buf.slice(off, off + bodyLen);
  const packet = cborDecode(bodyBytes) as Packet;
  return { packet, bodyBytes };
}
