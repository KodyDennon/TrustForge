/**
 * Binary framing for .tflog and .tfproof. Matches
 * `crates/tf-types/src/format.rs` byte-for-byte via
 * `conformance/framing-vectors.yaml`.
 *
 * .tflog  — append-only log of proof events.
 *   header  = "TFLOG\x01\x00\x00"   (8 bytes)
 *   frames  = u32 BE length + canonical-JSON event bytes (repeat)
 *
 * .tfproof — signed bundle container.
 *   header  = "TFPROOF\x01"           (8 bytes)
 *   body    = u32 BE length + canonical-JSON bundle bytes
 *   trailer = u32 BE length + raw signature bytes
 */

import type { ProofBundle } from "../generated/proof-bundle.js";
import type { ProofEvent } from "../generated/proof-event.js";
import { canonicalize } from "./canonical.js";
import { utf8decode, utf8encode } from "./crypto.js";

export const TFLOG_MAGIC = new Uint8Array([0x54, 0x46, 0x4c, 0x4f, 0x47, 0x01, 0x00, 0x00]);
export const TFPROOF_MAGIC = new Uint8Array([0x54, 0x46, 0x50, 0x52, 0x4f, 0x4f, 0x46, 0x01]);

export class FormatError extends Error {}

function putU32BE(view: number[], n: number): void {
  if (n < 0 || n > 0xffffffff) throw new FormatError(`length out of range: ${n}`);
  view.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function readU32BE(buf: Uint8Array, off: number): number {
  if (off + 4 > buf.length) throw new FormatError(`truncated at offset ${off}`);
  return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
}

function toBuf(parts: number[] | Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += (p as any).length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    if (Array.isArray(p)) {
      for (const b of p) {
        out[off++] = b;
      }
    } else {
      out.set(p as Uint8Array, off);
      off += (p as Uint8Array).length;
    }
  }
  return out;
}

// ---------- .tflog ----------

export function writeTflog(events: readonly ProofEvent[]): Uint8Array {
  const chunks: Uint8Array[] = [TFLOG_MAGIC];
  for (const e of events) {
    const body = utf8encode(canonicalize(e));
    const len: number[] = [];
    putU32BE(len, body.length);
    chunks.push(new Uint8Array(len));
    chunks.push(body);
  }
  return toBuf(chunks);
}

export function appendTflog(existing: Uint8Array, event: ProofEvent): Uint8Array {
  if (existing.length === 0) {
    return writeTflog([event]);
  }
  for (let i = 0; i < TFLOG_MAGIC.length; i++) {
    if (existing[i] !== TFLOG_MAGIC[i]) throw new FormatError("bad .tflog magic");
  }
  const body = utf8encode(canonicalize(event));
  const out = new Uint8Array(existing.length + 4 + body.length);
  out.set(existing, 0);
  const view = new DataView(out.buffer, out.byteOffset + existing.length, 4);
  view.setUint32(0, body.length, false);
  out.set(body, existing.length + 4);
  return out;
}

export function readTflog(buf: Uint8Array): ProofEvent[] {
  if (buf.length < TFLOG_MAGIC.length) throw new FormatError("truncated magic");
  for (let i = 0; i < TFLOG_MAGIC.length; i++) {
    if (buf[i] !== TFLOG_MAGIC[i]) throw new FormatError("bad .tflog magic");
  }
  const out: ProofEvent[] = [];
  let off = TFLOG_MAGIC.length;
  while (off < buf.length) {
    const len = readU32BE(buf, off);
    off += 4;
    if (off + len > buf.length) throw new FormatError(`truncated frame at offset ${off - 4}`);
    const text = utf8decode(buf.subarray(off, off + len));
    out.push(JSON.parse(text) as ProofEvent);
    off += len;
  }
  return out;
}

// ---------- .tfproof ----------

export interface TfproofParts {
  readonly bundle: ProofBundle;
  readonly signature: Uint8Array;
  readonly canonicalBody: Uint8Array;
}

export function writeTfproof(bundle: ProofBundle, signature: Uint8Array): Uint8Array {
  const body = utf8encode(canonicalize(bundle));
  const len1: number[] = [];
  putU32BE(len1, body.length);
  const len2: number[] = [];
  putU32BE(len2, signature.length);
  return toBuf([TFPROOF_MAGIC, new Uint8Array(len1), body, new Uint8Array(len2), signature]);
}

export function readTfproof(buf: Uint8Array): TfproofParts {
  if (buf.length < TFPROOF_MAGIC.length) throw new FormatError("truncated magic");
  for (let i = 0; i < TFPROOF_MAGIC.length; i++) {
    if (buf[i] !== TFPROOF_MAGIC[i]) throw new FormatError("bad .tfproof magic");
  }
  let off = TFPROOF_MAGIC.length;
  const bodyLen = readU32BE(buf, off);
  off += 4;
  if (off + bodyLen > buf.length) throw new FormatError("truncated body");
  const canonicalBody = buf.subarray(off, off + bodyLen);
  const bundle = JSON.parse(utf8decode(canonicalBody)) as ProofBundle;
  off += bodyLen;
  const sigLen = readU32BE(buf, off);
  off += 4;
  if (off + sigLen > buf.length) throw new FormatError("truncated signature");
  const signature = buf.slice(off, off + sigLen);
  return { bundle, signature, canonicalBody };
}
