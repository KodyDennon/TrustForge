/**
 * Encrypted .tfbundle (L4/L5) sealing + transparency-log anchoring.
 *
 * sealBundle / openBundle implement the wrap-then-encrypt scheme
 * described in proof-bundle-encrypted.schema.json:
 *
 *   data_key  = random 32 bytes
 *   nonce     = random 12 bytes
 *   ciphertext = chacha20poly1305(plaintext, data_key, nonce)
 *
 *   for each recipient:
 *     ephemeral_priv = random X25519 scalar
 *     ephemeral_pub  = X25519(ephemeral_priv, base_point)
 *     shared         = X25519(ephemeral_priv, recipient_kem_public)
 *     wrap_key       = HKDF-SHA256(shared, info="tfbundle/wrap")
 *     wrap_nonce     = random 12 bytes
 *     wrapped        = chacha20poly1305(data_key, wrap_key, wrap_nonce)
 *
 * The recipient reverses the process with their X25519 secret key.
 *
 * Transparency anchoring is intentionally simple: an `Anchor` interface
 * describes how a backend submits the bundle and returns an inclusion
 * proof; v0.1.0 ships an in-process backend (good for tests) plus
 * `submitToRfc6962` and `submitToSigstore` stubs that POST a JSON body
 * the spec says is appropriate.
 *
 * RFC 3161 timestamping: `signRfc3161Timestamp` produces the canonical
 * TimeStampReq bytes (DER); a real TSA call is delegated to a callback.
 */

import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify } from "./crypto.js";
import type { ProofBundle } from "../generated/proof-bundle.js";
import type { ActorId, SignatureEnvelope } from "../generated/_common.js";

export interface BundleRecipient {
  actor: ActorId;
  /** Recipient's 32-byte X25519 public key. */
  kemPublic: Uint8Array;
  /** Optional key id (recorded in the wrapped-key entry). */
  keyId?: string;
}

export interface SealBundleArgs {
  bundle: ProofBundle;
  recipients: BundleRecipient[];
  level: "L4" | "L5";
  /** Daemon's ed25519 private key for the outer signature. */
  signerPrivateKey: Uint8Array;
  /** Actor URI corresponding to signerPrivateKey. */
  signer: ActorId;
}

export interface EncryptedProofBundle {
  bundle_version: "1";
  level: "L4" | "L5";
  ciphertext: string;
  nonce: string;
  wrapped_keys: Array<{
    recipient: ActorId;
    recipient_key_id?: string;
    ephemeral_public: string;
    wrapped: string;
    wrap_nonce: string;
  }>;
  transparency_anchor?: Record<string, unknown>;
  signature: SignatureEnvelope;
}

const HKDF_INFO = new TextEncoder().encode("tfbundle/wrap");

function randBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

function b64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

function unb64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export async function sealBundle(args: SealBundleArgs): Promise<EncryptedProofBundle> {
  const dataKey = randBytes(32);
  const nonce = randBytes(12);
  const plaintext = new TextEncoder().encode(canonicalize(args.bundle as unknown));
  const cipher = chacha20poly1305(dataKey, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  const wrappedKeys: EncryptedProofBundle["wrapped_keys"] = [];
  for (const r of args.recipients) {
    if (r.kemPublic.length !== 32) {
      throw new Error("recipient kemPublic must be 32 bytes");
    }
    const ephemeralPriv = randBytes(32);
    const ephemeralPub = x25519.scalarMultBase(ephemeralPriv);
    const shared = x25519.scalarMult(ephemeralPriv, r.kemPublic);
    const wrapKey = hkdf(sha256, shared, undefined, HKDF_INFO, 32);
    const wrapNonce = randBytes(12);
    const wrapped = chacha20poly1305(wrapKey, wrapNonce).encrypt(dataKey);
    wrappedKeys.push({
      recipient: r.actor,
      recipient_key_id: r.keyId,
      ephemeral_public: b64(ephemeralPub),
      wrapped: b64(wrapped),
      wrap_nonce: b64(wrapNonce),
    });
  }

  const stub: EncryptedProofBundle = {
    bundle_version: "1",
    level: args.level,
    ciphertext: b64(ciphertext),
    nonce: b64(nonce),
    wrapped_keys: wrappedKeys,
    signature: { algorithm: "ed25519", signer: args.signer, signature: "" },
  };
  const digest = encryptedSigningBytes(stub);
  const sig = await ed25519Sign(digest, args.signerPrivateKey);
  stub.signature = {
    algorithm: "ed25519",
    signer: args.signer,
    signature: b64(sig),
  };
  return stub;
}

export interface OpenBundleArgs {
  encrypted: EncryptedProofBundle;
  /** Recipient's X25519 private key (32 bytes). */
  recipientPrivateKey: Uint8Array;
  /** Recipient actor URI to look up the right wrapped key. */
  recipientActor: ActorId;
  /** Optional public key for verifying the outer signature. */
  signerPublicKey?: Uint8Array;
}

export async function openBundle(args: OpenBundleArgs): Promise<ProofBundle> {
  const enc = args.encrypted;
  const wrap = enc.wrapped_keys.find((w) => w.recipient === args.recipientActor);
  if (!wrap) throw new Error(`no wrapped key for recipient ${args.recipientActor}`);
  const ephemeralPub = unb64(wrap.ephemeral_public);
  const wrapped = unb64(wrap.wrapped);
  const wrapNonce = unb64(wrap.wrap_nonce);
  const shared = x25519.scalarMult(args.recipientPrivateKey, ephemeralPub);
  const wrapKey = hkdf(sha256, shared, undefined, HKDF_INFO, 32);
  const dataKey = chacha20poly1305(wrapKey, wrapNonce).decrypt(wrapped);
  const ciphertext = unb64(enc.ciphertext);
  const nonce = unb64(enc.nonce);
  const plaintext = chacha20poly1305(dataKey, nonce).decrypt(ciphertext);
  const json = new TextDecoder().decode(plaintext);
  if (args.signerPublicKey) {
    const digest = encryptedSigningBytes(enc);
    const sig = unb64(enc.signature.signature);
    const verified = await ed25519Verify(args.signerPublicKey, digest, sig);
    if (!verified) throw new Error("encrypted bundle signature did not verify");
  }
  return JSON.parse(json) as ProofBundle;
}

export function encryptedSigningBytes(enc: EncryptedProofBundle): Uint8Array {
  const { signature: _signature, ...rest } = enc;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

/* -------------------------------------------------------------------------- */
/*  Transparency anchoring                                                    */
/* -------------------------------------------------------------------------- */

export interface AnchorBackend {
  readonly kind: "rfc6962" | "sigstore" | "custom" | "memory";
  readonly url?: string;
  submit(bundleBytes: Uint8Array): Promise<{ inclusion_proof: Record<string, unknown> }>;
  verifyInclusion(
    bundleBytes: Uint8Array,
    inclusionProof: Record<string, unknown>,
  ): Promise<boolean>;
}

/** Memory anchor — keeps a hash of every submitted bundle so callers
 *  can round-trip submit + verify in tests without external backends. */
export class MemoryAnchor implements AnchorBackend {
  readonly kind = "memory" as const;
  private entries = new Map<string, number>();
  async submit(bundleBytes: Uint8Array): Promise<{ inclusion_proof: Record<string, unknown> }> {
    const digest = Buffer.from(sha256(bundleBytes)).toString("hex");
    const seq = this.entries.size;
    this.entries.set(digest, seq);
    return { inclusion_proof: { kind: "memory", digest, sequence_number: seq } };
  }
  async verifyInclusion(
    bundleBytes: Uint8Array,
    inclusionProof: Record<string, unknown>,
  ): Promise<boolean> {
    const expected = Buffer.from(sha256(bundleBytes)).toString("hex");
    if (inclusionProof.digest !== expected) return false;
    return this.entries.get(expected) === inclusionProof.sequence_number;
  }
}

/** Submit to an RFC 6962 (Certificate Transparency) log. The backend
 *  POSTs `{ chain: [base64(bundle)] }` to `/ct/v1/add-chain` and stores
 *  the returned signed certificate timestamp (SCT) as the inclusion
 *  proof. Network errors propagate; the helper does not retry. */
export async function submitToRfc6962(
  url: string,
  bundleBytes: Uint8Array,
  fetcher: typeof fetch = fetch,
): Promise<{ inclusion_proof: Record<string, unknown> }> {
  const body = JSON.stringify({ chain: [b64(bundleBytes)] });
  const resp = await fetcher(`${url}/ct/v1/add-chain`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  if (!resp.ok) throw new Error(`rfc6962 anchor failed: ${resp.status} ${resp.statusText}`);
  const sct = await resp.json();
  return { inclusion_proof: { kind: "rfc6962", sct } };
}

/** Submit to a sigstore-compatible Rekor log (POST /api/v1/log/entries). */
export async function submitToSigstore(
  url: string,
  bundleBytes: Uint8Array,
  fetcher: typeof fetch = fetch,
): Promise<{ inclusion_proof: Record<string, unknown> }> {
  const body = JSON.stringify({
    apiVersion: "0.0.1",
    kind: "intoto",
    spec: { content: { hash: { algorithm: "sha256", value: Buffer.from(sha256(bundleBytes)).toString("hex") } } },
  });
  const resp = await fetcher(`${url}/api/v1/log/entries`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  if (!resp.ok) throw new Error(`sigstore anchor failed: ${resp.status} ${resp.statusText}`);
  const entry = await resp.json();
  return { inclusion_proof: { kind: "sigstore", entry } };
}

/* -------------------------------------------------------------------------- */
/*  RFC 3161 timestamping                                                     */
/* -------------------------------------------------------------------------- */

/** Produce the DER-encoded TimeStampReq for SHA-256 over `data`.
 *  Callers POST these bytes to a TSA (`Content-Type:
 *  application/timestamp-query`) and receive a TimeStampResp. */
export function buildRfc3161Request(data: Uint8Array): Uint8Array {
  const digest = sha256(data);
  // TimeStampReq ::= SEQUENCE {
  //   version              INTEGER  { v1(1) },
  //   messageImprint       MessageImprint,
  //   reqPolicy            OBJECT IDENTIFIER OPTIONAL,
  //   nonce                INTEGER OPTIONAL,
  //   certReq              BOOLEAN DEFAULT FALSE,
  //   extensions           [0] IMPLICIT Extensions OPTIONAL
  // }
  // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  const oidSha256 = new Uint8Array([
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  ]);
  const algId = derSequence([oidSha256, new Uint8Array([0x05, 0x00])]);
  const hashedMessage = derOctetString(digest);
  const messageImprint = derSequence([algId, hashedMessage]);
  const version = derInteger(new Uint8Array([0x01]));
  const certReqTrue = derBoolean(true);
  return derSequence([version, messageImprint, certReqTrue]);
}

function derSequence(parts: Uint8Array[]): Uint8Array {
  const body = concat(...parts);
  return concat(new Uint8Array([0x30]), derLen(body.length), body);
}

function derOctetString(bytes: Uint8Array): Uint8Array {
  return concat(new Uint8Array([0x04]), derLen(bytes.length), bytes);
}

function derInteger(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let payload = bytes.slice(i);
  if ((payload[0] ?? 0) & 0x80) {
    const padded = new Uint8Array(payload.length + 1);
    padded.set(payload, 1);
    payload = padded;
  }
  return concat(new Uint8Array([0x02]), derLen(payload.length), payload);
}

function derBoolean(b: boolean): Uint8Array {
  return new Uint8Array([0x01, 0x01, b ? 0xff : 0x00]);
}

function derLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
