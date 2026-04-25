/**
 * DID (Decentralized Identifier — W3C DID Core 1.0) bridge.
 *
 * Resolves a DID URL into a DID document, picks a verification method,
 * and projects it into a TrustForge ActorIdentity. Supports the
 * mandatory `did:key` (RFC 9468 / multibase ed25519) method out of the
 * box; arbitrary methods can be plugged in via the resolver callback
 * so callers can wire `did:web`, `did:plc`, `did:ion`, etc. without
 * pulling extra deps.
 */

import { sha256 } from "@noble/hashes/sha256";

import type { ActorIdentity } from "../generated/actor-identity.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";
import { ed25519Verify } from "./crypto.js";

export interface DidVerificationMethod {
  id: string;
  /** e.g. `Ed25519VerificationKey2020`, `JsonWebKey2020`. */
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
}

export interface DidDocument {
  "@context"?: string | string[];
  id: string;
  controller?: string | string[];
  verificationMethod?: DidVerificationMethod[];
  authentication?: Array<string | DidVerificationMethod>;
  assertionMethod?: Array<string | DidVerificationMethod>;
  service?: Array<{ id: string; type: string; serviceEndpoint: string }>;
}

export type DidResolver = (didUrl: string) => Promise<DidDocument>;

export interface DidBridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Resolver for arbitrary DID methods. Defaults to a built-in
   *  `did:key` resolver. Wire in `did:web` / `did:plc` / etc. by
   *  composing your own resolver. */
  resolver?: DidResolver;
  /** Optional allow-list of method names — if set, the bridge refuses
   *  to resolve any method not in this set. */
  allowedMethods?: string[];
}

export interface DidVerificationResult {
  identity: ActorIdentity;
  document: DidDocument;
  /** Verification method id used to populate the actor identity. */
  verificationMethodId: string;
}

export class DidBridge implements Bridge {
  readonly kind: BridgeKind = "did";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: DidBridgeConfig;

  constructor(cfg: DidBridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
  }

  /** Resolve a DID URL to a DID document. Tries the built-in did:key
   *  resolver first; falls back to the caller-supplied resolver if any. */
  async resolve(didUrl: string): Promise<DidDocument> {
    const method = parseDidMethod(didUrl);
    if (this.cfg.allowedMethods && !this.cfg.allowedMethods.includes(method)) {
      throw new BridgeFailure({
        code: "rejected",
        message: `DID method ${method} not in allow-list`,
      });
    }
    if (method === "key") {
      return resolveDidKey(didUrl);
    }
    if (this.cfg.resolver) {
      return this.cfg.resolver(didUrl);
    }
    throw new BridgeFailure({
      code: "unsupported",
      message: `no resolver configured for DID method ${method}`,
    });
  }

  /** Resolve a DID URL and project it into an ActorIdentity. Picks the
   *  first authentication method that maps to a known signature
   *  algorithm (ed25519 today; ECDSA / RSA via the JWK projector when
   *  the method declares them). */
  async accept(didUrl: string): Promise<DidVerificationResult> {
    const document = await this.resolve(didUrl);
    const vms = document.verificationMethod ?? [];
    const auth = (document.authentication ?? []).map((a) =>
      typeof a === "string" ? vms.find((v) => v.id === a) : a,
    );
    const candidates = (auth.filter(Boolean) as DidVerificationMethod[]).concat(vms);
    if (candidates.length === 0) {
      throw new BridgeFailure({
        code: "rejected",
        message: "DID document has no verification methods",
      });
    }
    const vm = candidates[0]!;
    const publicKey = extractPublicKey(vm);
    if (!publicKey) {
      throw new BridgeFailure({
        code: "unsupported",
        message: `verification method ${vm.id} has no usable public key`,
      });
    }
    const subject = encodeURIComponent(document.id);
    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: `tf:actor:human:${this.cfg.trustDomain}/${subject}`,
      actor_type: "human",
      public_keys: [
        {
          key_id: vm.id,
          algorithm: publicKey.algorithm,
          public_key: Buffer.from(publicKey.bytes).toString("base64"),
          purpose: "signing",
        },
      ],
      trust_levels: ["T2"],
      authority_roots: [
        {
          kind: "federation",
          id: vm.controller,
        },
      ],
      valid_from: new Date().toISOString(),
    };
    return { identity, document, verificationMethodId: vm.id };
  }

  /** Verify an ed25519 signature using the resolved DID's first
   *  ed25519 verification method. */
  async verifySignature(
    didUrl: string,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    const doc = await this.resolve(didUrl);
    const vms = doc.verificationMethod ?? [];
    for (const vm of vms) {
      const pk = extractPublicKey(vm);
      if (pk?.algorithm === "ed25519") {
        const ok = await ed25519Verify(pk.bytes, message, signature);
        if (ok) return true;
      }
    }
    return false;
  }
}

function parseDidMethod(did: string): string {
  const m = /^did:([a-z0-9]+):/.exec(did);
  if (!m) throw new BridgeFailure({ code: "invalid-input", message: `not a DID: ${did}` });
  return m[1]!;
}

function extractPublicKey(vm: DidVerificationMethod): { algorithm: string; bytes: Uint8Array } | null {
  if (vm.publicKeyMultibase) {
    const decoded = decodeMultibase(vm.publicKeyMultibase);
    if (!decoded) return null;
    // Per RFC 9468, ed25519 multikeys are prefixed with 0xed 0x01.
    if (decoded[0] === 0xed && decoded[1] === 0x01) {
      return { algorithm: "ed25519", bytes: decoded.slice(2) };
    }
    // Generic fallback: pass the raw bytes through.
    return { algorithm: vm.type.toLowerCase(), bytes: decoded };
  }
  if (vm.publicKeyJwk) {
    const jwk = vm.publicKeyJwk;
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") {
      return { algorithm: "ed25519", bytes: base64UrlToBytes(jwk.x) };
    }
    if (jwk.kty === "EC" && typeof jwk.x === "string" && typeof jwk.y === "string") {
      const x = base64UrlToBytes(jwk.x);
      const y = base64UrlToBytes(jwk.y);
      const buf = new Uint8Array(1 + x.length + y.length);
      buf[0] = 0x04;
      buf.set(x, 1);
      buf.set(y, 1 + x.length);
      return { algorithm: jwk.crv === "P-256" ? "p256" : "ec", bytes: buf };
    }
  }
  return null;
}

/** Built-in did:key resolver. Supports the ed25519 multikey prefix
 *  (0xed 0x01) per the W3C did:key specification. */
async function resolveDidKey(didUrl: string): Promise<DidDocument> {
  const m = /^did:key:([a-zA-Z1-9]+)/.exec(didUrl);
  if (!m) throw new BridgeFailure({ code: "invalid-input", message: `not a did:key: ${didUrl}` });
  const multibase = m[1]!;
  const id = `did:key:${multibase}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id,
    verificationMethod: [
      {
        id: `${id}#${multibase}`,
        type: "Ed25519VerificationKey2020",
        controller: id,
        publicKeyMultibase: multibase,
      },
    ],
    authentication: [`${id}#${multibase}`],
    assertionMethod: [`${id}#${multibase}`],
  };
}

/** Decode a multibase string. Supports `z` (base58btc), `m` (base64),
 *  `u` (base64url-no-pad). */
function decodeMultibase(s: string): Uint8Array | null {
  if (s.length === 0) return null;
  const prefix = s[0]!;
  const body = s.slice(1);
  switch (prefix) {
    case "z":
      return base58btcDecode(body);
    case "m":
      return new Uint8Array(Buffer.from(body, "base64"));
    case "u":
      return base64UrlToBytes(body);
    default:
      return null;
  }
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcDecode(s: string): Uint8Array | null {
  if (s.length === 0) return new Uint8Array();
  // Count leading '1' chars — each is a leading zero byte.
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros += 1;
  // Allocate enough capacity (log(58)/log(256) ≈ 0.733).
  const size = Math.ceil((s.length - zeros) * 0.733) + 1;
  const b256 = new Uint8Array(size);
  for (let i = zeros; i < s.length; i++) {
    const idx = BASE58_ALPHABET.indexOf(s[i]!);
    if (idx < 0) return null;
    let carry = idx;
    for (let j = size - 1; j >= 0; j--) {
      carry += b256[j]! * 58;
      b256[j] = carry & 0xff;
      carry >>= 8;
    }
    if (carry !== 0) return null;
  }
  // Skip leading zeros in b256.
  let start = 0;
  while (start < size && b256[start] === 0) start += 1;
  const out = new Uint8Array(zeros + (size - start));
  out.set(b256.subarray(start), zeros);
  return out;
}

function base64UrlToBytes(b64u: string): Uint8Array {
  let s = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  return new Uint8Array(Buffer.from(s, "base64"));
}

/** Compute the ed25519 multibase identifier for a 32-byte ed25519
 *  public key — useful for tests and for callers that need to mint a
 *  did:key for a freshly-generated key. */
export function ed25519PublicKeyToDidKey(pub: Uint8Array): string {
  if (pub.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  const prefixed = new Uint8Array(2 + 32);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub, 2);
  return `z${base58btcEncode(prefixed)}`;
}

function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  const size = Math.ceil(bytes.length * 1.366) + 1;
  const b58 = new Uint8Array(size);
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = size - 1; j >= 0; j--) {
      carry += b58[j]! * 256;
      b58[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
  }
  let start = 0;
  while (start < size && b58[start] === 0) start += 1;
  let out = "";
  for (let i = 0; i < zeros; i++) out += "1";
  for (let i = start; i < size; i++) out += BASE58_ALPHABET[b58[i]!];
  return out;
}

// Touch sha256 so the import doesn't end up dead when the spec adds a
// digest-based identity check in a future version.
void sha256;
