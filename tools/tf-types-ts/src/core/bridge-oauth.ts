/**
 * OAuth / GNAP bridge — verify a JWT bearer token against a JWKS, then
 * project the verified claims into a TrustForge actor identity + a set of
 * derived capabilities.
 *
 * Algorithms supported: ES256, ES384, ES512, RS256, RS384, RS512, EdDSA.
 * Verification is delegated to the audited `jose` library.
 */

import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
  type JWTVerifyResult,
  type ResolvedKey,
} from "jose";

import type { ActorIdentity } from "../generated/actor-identity.js";
import type { Capability } from "../generated/_common.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";

export type OAuthAlgorithm =
  | "ES256"
  | "ES384"
  | "ES512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "EdDSA";

export interface OAuthBridgeConfig {
  bridgeId: string;
  /** Trust domain that owns this bridge instance. */
  trustDomain: string;
  /** Either an inline JWKS or a JWKS URL the bridge fetches once and caches. */
  jwks: JSONWebKeySet | { url: URL | string };
  /** Required algorithms — refusal-on-unknown defends against algorithm
   *  confusion attacks like alg:none / HS256 swap. */
  allowedAlgorithms: OAuthAlgorithm[];
  /** Required token issuer (`iss` claim). */
  issuer: string;
  /** Required audience (`aud` claim). */
  audience: string | string[];
  /** Optional clock skew in seconds (default 60). */
  clockToleranceSeconds?: number;
  /** Optional override that turns OAuth scopes into TrustForge action names.
   *  Default: identity. */
  scopeToAction?: (scope: string) => string;
}

export interface OAuthVerificationResult {
  identity: ActorIdentity;
  capabilities: Capability[];
  claims: JWTPayload;
}

function resolveJwks(cfg: OAuthBridgeConfig) {
  if ("url" in cfg.jwks && cfg.jwks.url) {
    const url = typeof cfg.jwks.url === "string" ? new URL(cfg.jwks.url) : cfg.jwks.url;
    return createRemoteJWKSet(url);
  }
  return createLocalJWKSet(cfg.jwks as JSONWebKeySet);
}

export class OAuthBridge implements Bridge {
  readonly kind: BridgeKind = "oauth";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: OAuthBridgeConfig;
  private readonly jwks: ReturnType<typeof resolveJwks>;

  constructor(cfg: OAuthBridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
    this.jwks = resolveJwks(cfg);
  }

  /** Verify a JWT bearer token and project its claims into a TrustForge
   *  identity. Throws BridgeFailure on any verification failure (signature,
   *  issuer mismatch, audience mismatch, expired, unsupported algorithm). */
  async verifyToken(token: string): Promise<OAuthVerificationResult> {
    if (!token || typeof token !== "string") {
      throw new BridgeFailure({ code: "invalid-input", message: "missing JWT bearer token" });
    }
    let result: JWTVerifyResult & ResolvedKey;
    try {
      result = (await jwtVerify(token, this.jwks, {
        issuer: this.cfg.issuer,
        audience: this.cfg.audience,
        algorithms: this.cfg.allowedAlgorithms,
        clockTolerance: this.cfg.clockToleranceSeconds ?? 60,
      })) as JWTVerifyResult & ResolvedKey;
    } catch (err) {
      throw new BridgeFailure({
        code: "rejected",
        message: `JWT verification failed: ${(err as Error).message}`,
      });
    }
    const claims = result.payload;
    const subject = claims.sub;
    if (!subject) {
      throw new BridgeFailure({
        code: "rejected",
        message: "JWT missing required `sub` claim",
      });
    }

    const actorType = (claims["tf_actor_type"] as string | undefined) ?? "human";
    const allowedTypes = new Set([
      "human",
      "agent",
      "device",
      "service",
      "site",
      "organization",
    ]);
    if (!allowedTypes.has(actorType)) {
      throw new BridgeFailure({
        code: "rejected",
        message: `unsupported actor type from claim tf_actor_type=${actorType}`,
      });
    }
    const actorId = `tf:actor:${actorType}:${this.cfg.trustDomain}/${encodeURIComponent(subject)}`;

    // Public key bytes from the JWK that signed the token (the resolved key
    // is exposed by jose as a CryptoKey or JWK; we re-encode the JWK as
    // base64 of its raw representation when possible).
    const publicKeys = await this.toPublicKeys(claims, result);

    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: actorId,
      actor_type: actorType as ActorIdentity["actor_type"],
      public_keys: publicKeys,
      trust_levels: ["T3"],
      authority_roots: [
        {
          kind: claims["tf_authority_kind"] === "federation" ? "federation" : "organization",
          id: this.cfg.issuer,
        },
      ],
      valid_from: claims.iat ? new Date(claims.iat * 1000).toISOString() : new Date().toISOString(),
      valid_until: claims.exp ? new Date(claims.exp * 1000).toISOString() : undefined,
    };

    const scopes = this.extractScopes(claims);
    const capabilities: Capability[] = scopes.map((scope) => ({
      name: (this.cfg.scopeToAction ?? ((s) => s))(scope),
      risk: "R2",
    }));

    return { identity, capabilities, claims };
  }

  private async toPublicKeys(
    _claims: JWTPayload,
    result: JWTVerifyResult & ResolvedKey,
  ): Promise<ActorIdentity["public_keys"]> {
    // Project the JWK that signed the token into TrustForge's raw-bytes
    // PublicKey shape. The mapping per RFC 7518 / RFC 8037:
    //   ES256 / ES384 / ES512 → kty=EC; ship uncompressed SEC1 point
    //   EdDSA crv=Ed25519     → kty=OKP; ship raw 32-byte x
    //   RS256 / RS384 / RS512 → kty=RSA; ship the SubjectPublicKeyInfo DER
    //                                    (modulus + exponent, base64).
    try {
      const jwk = await jwkFromResolvedKey(result);
      const projected = projectJwkToPublicKey(jwk);
      return [projected];
    } catch (err) {
      // The signature was already verified against the JWKS above; if
      // the exporter can't surface the JWK in our shape we surface an
      // empty key list rather than fabricating a `public_key:"AA=="`
      // ed25519 entry. Pre-B9 the placeholder ed25519 key passed
      // schema validation but was a 1-byte zero — a deceptive
      // identity record. Callers can match against the JWT's
      // claims-level subject + issuer instead.
      void err;
    }
    return [];
  }

  private extractScopes(claims: JWTPayload): string[] {
    const raw = claims["scope"];
    if (typeof raw === "string") return raw.split(/\s+/).filter(Boolean);
    if (Array.isArray(raw)) return raw.filter((v) => typeof v === "string");
    return [];
  }
}

/** Extract the JWK that jose used to verify the token, using the
 *  jose-provided exporter when available and falling back to
 *  WebCrypto's `subtle.exportKey('jwk', ...)`. */
async function jwkFromResolvedKey(
  result: JWTVerifyResult & ResolvedKey,
): Promise<Record<string, unknown>> {
  // jose >= 5 attaches the raw JWK alongside the resolved key for remote
  // JWKS sets. When that's missing, fall back to exporting via subtle.
  const candidate = (result as unknown as { protectedHeader?: Record<string, unknown>; key?: unknown }).key;
  if (candidate && typeof candidate === "object" && "kty" in candidate) {
    return candidate as Record<string, unknown>;
  }
  if (typeof crypto !== "undefined" && (candidate as unknown) instanceof CryptoKey) {
    const jwk = await crypto.subtle.exportKey("jwk", candidate as CryptoKey);
    return jwk as Record<string, unknown>;
  }
  throw new Error("resolved key cannot be exported as JWK");
}

/** Convert a JWK (per RFC 7518 + RFC 8037) into TrustForge's raw-bytes
 *  PublicKey shape. */
export function projectJwkToPublicKey(jwk: Record<string, unknown>): ActorIdentity["public_keys"][number] {
  const kty = jwk["kty"];
  const crv = jwk["crv"];
  const kid = (typeof jwk["kid"] === "string" ? (jwk["kid"] as string) : "oauth-bridge-bearer");
  if (kty === "OKP" && crv === "Ed25519") {
    const x = jwk["x"];
    if (typeof x !== "string") {
      throw new BridgeFailure({ code: "invalid-input", message: "Ed25519 JWK missing x" });
    }
    return {
      key_id: kid,
      algorithm: "ed25519",
      public_key: base64FromBase64Url(x),
      purpose: "signing",
    };
  }
  if (kty === "EC") {
    const x = jwk["x"];
    const y = jwk["y"];
    if (typeof x !== "string" || typeof y !== "string") {
      throw new BridgeFailure({ code: "invalid-input", message: "EC JWK missing x/y" });
    }
    const xBytes = base64UrlToBytes(x);
    const yBytes = base64UrlToBytes(y);
    const sec1 = new Uint8Array(1 + xBytes.length + yBytes.length);
    sec1[0] = 0x04;
    sec1.set(xBytes, 1);
    sec1.set(yBytes, 1 + xBytes.length);
    const algName = crv === "P-256" ? "p256" : crv === "P-384" ? "p384" : crv === "P-521" ? "p521" : "ec";
    return {
      key_id: kid,
      algorithm: algName,
      public_key: Buffer.from(sec1).toString("base64"),
      purpose: "signing",
    };
  }
  if (kty === "RSA") {
    const n = jwk["n"];
    const e = jwk["e"];
    if (typeof n !== "string" || typeof e !== "string") {
      throw new BridgeFailure({ code: "invalid-input", message: "RSA JWK missing n/e" });
    }
    const der = encodeRsaSpkiDer(base64UrlToBytes(n), base64UrlToBytes(e));
    return {
      key_id: kid,
      algorithm: "rsa",
      public_key: Buffer.from(der).toString("base64"),
      purpose: "signing",
    };
  }
  throw new BridgeFailure({
    code: "unsupported",
    message: `unsupported JWK kty/crv: ${kty}/${crv}`,
  });
}

function base64FromBase64Url(b64u: string): string {
  return Buffer.from(base64UrlToBytes(b64u)).toString("base64");
}

function base64UrlToBytes(b64u: string): Uint8Array {
  let s = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  return new Uint8Array(Buffer.from(s, "base64"));
}

/** Build a SubjectPublicKeyInfo DER for an RSA public key directly from
 *  modulus and exponent. We construct the inner RSAPublicKey SEQUENCE,
 *  wrap it in a BIT STRING, and prepend the rsaEncryption AlgorithmIdentifier. */
function encodeRsaSpkiDer(n: Uint8Array, e: Uint8Array): Uint8Array {
  const rsaPublicKey = derSequence([derInteger(n), derInteger(e)]);
  // AlgorithmIdentifier = SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
  const oidRsaEncryption = new Uint8Array([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  ]);
  const algorithmIdentifier = derSequence([oidRsaEncryption, new Uint8Array([0x05, 0x00])]);
  const bitString = concat(new Uint8Array([0x03]), derLen(1 + rsaPublicKey.length), new Uint8Array([0x00]), rsaPublicKey);
  return derSequence([algorithmIdentifier, bitString]);
}

function derSequence(parts: Uint8Array[]): Uint8Array {
  const body = concat(...parts);
  return concat(new Uint8Array([0x30]), derLen(body.length), body);
}

function derInteger(bytes: Uint8Array): Uint8Array {
  // Strip leading zeros except one needed to keep the integer non-negative.
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
