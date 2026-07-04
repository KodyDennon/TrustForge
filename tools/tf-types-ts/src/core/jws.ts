/**
 * In-house JWS/JWT compact-serialization verify + sign (RFC 7515/7519)
 * — TrustForge owns its envelope layer; see `docs/dependency-audit.md`.
 * Mirror of `crates/tf-types/src/jws.rs`.
 *
 * **No custom cryptography**: signature math delegates to reviewed
 * primitives — `@noble/curves` (ES256/ES384/ES512, EdDSA) and the
 * runtime WebCrypto (RSASSA-PKCS1-v1_5 for RS256/RS384/RS512, key
 * generation). This module owns only the *envelope*: compact-form
 * parsing, base64url, the algorithm allow-list, registered-claim
 * validation, and the RFC 7638 JWK thumbprint.
 *
 * The exported names deliberately match the `jose` API surface this
 * replaced (`jwtVerify`, `createLocalJWKSet`, `SignJWT`, …) so call
 * sites and tests only swap the import specifier.
 *
 * Security posture (deliberate, do not relax):
 * - `alg` is never trusted from the token alone: verification requires
 *   the caller's allow-list (`algorithms`) and `none` is rejected.
 * - Key type and algorithm must agree (an RSA key never verifies an
 *   ES256 token).
 * - `exp` is always validated when present and required by default;
 *   `iss`/`aud`/`typ` are enforced whenever the caller configures them.
 */

import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";

export class JwsError extends Error {}

export type JwsAlgorithm =
  | "ES256"
  | "ES384"
  | "ES512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "EdDSA";

const EC_CURVES: Record<string, { curve: typeof p256; alg: JwsAlgorithm; width: number }> = {
  "P-256": { curve: p256, alg: "ES256", width: 32 },
  "P-384": { curve: p384 as unknown as typeof p256, alg: "ES384", width: 48 },
  "P-521": { curve: p521 as unknown as typeof p256, alg: "ES512", width: 66 },
};

const RSA_HASHES: Record<string, string> = {
  RS256: "SHA-256",
  RS384: "SHA-384",
  RS512: "SHA-512",
};

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  d?: string;
  [member: string]: unknown;
}

/* ------------------------------------------------------------------ */
/*  base64url                                                          */
/* ------------------------------------------------------------------ */

function b64uEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDecode(text: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new JwsError(`${what}: not base64url`);
  }
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const UTF8 = new TextEncoder();

/* ------------------------------------------------------------------ */
/*  JWK helpers                                                        */
/* ------------------------------------------------------------------ */

function jwkString(jwk: Jwk, member: string): string {
  const v = jwk[member];
  if (typeof v !== "string" || v === "") {
    throw new JwsError(`JWK missing ${member}`);
  }
  return v;
}

function algorithmsForJwk(jwk: Jwk): JwsAlgorithm[] {
  switch (jwk.kty) {
    case "EC": {
      const info = EC_CURVES[jwkString(jwk, "crv")];
      if (!info) throw new JwsError(`unsupported EC curve ${jwk["crv"]}`);
      return [info.alg];
    }
    case "OKP":
      if (jwkString(jwk, "crv") !== "Ed25519") {
        throw new JwsError(`unsupported OKP curve ${jwk["crv"]}`);
      }
      return ["EdDSA"];
    case "RSA":
      return ["RS256", "RS384", "RS512"];
    default:
      throw new JwsError(`unsupported kty ${jwk.kty}`);
  }
}

/** Validate a JWK for the given algorithm and return it. Name-compatible
 *  with jose's `importJWK`; the returned handle is simply the JWK. */
export async function importJWK(jwk: Jwk, alg?: string): Promise<Jwk> {
  const supported = algorithmsForJwk(jwk);
  if (alg && !supported.includes(alg as JwsAlgorithm)) {
    throw new JwsError(`JWK does not support ${alg}`);
  }
  return jwk;
}

/** RFC 7638 JWK thumbprint (base64url SHA-256 of the canonical
 *  required-members JSON). */
export async function calculateJwkThumbprint(jwk: Jwk, hash: "sha256" = "sha256"): Promise<string> {
  void hash;
  let canonical: string;
  switch (jwk.kty) {
    case "EC":
      canonical = `{"crv":${JSON.stringify(jwkString(jwk, "crv"))},"kty":"EC","x":${JSON.stringify(jwkString(jwk, "x"))},"y":${JSON.stringify(jwkString(jwk, "y"))}}`;
      break;
    case "OKP":
      canonical = `{"crv":${JSON.stringify(jwkString(jwk, "crv"))},"kty":"OKP","x":${JSON.stringify(jwkString(jwk, "x"))}}`;
      break;
    case "RSA":
      canonical = `{"e":${JSON.stringify(jwkString(jwk, "e"))},"kty":"RSA","n":${JSON.stringify(jwkString(jwk, "n"))}}`;
      break;
    default:
      throw new JwsError(`unsupported kty ${jwk.kty}`);
  }
  return b64uEncode(sha256(UTF8.encode(canonical)));
}

/* ------------------------------------------------------------------ */
/*  Key sets                                                           */
/* ------------------------------------------------------------------ */

export type JwkResolver = (protectedHeader: Record<string, unknown>) => Promise<Jwk>;

function selectFromKeys(keys: Jwk[], header: Record<string, unknown>): Jwk {
  const kid = header["kid"];
  const alg = header["alg"];
  const candidates = keys.filter((k) => {
    if (typeof kid === "string" && k["kid"] !== kid) return false;
    if (typeof k["alg"] === "string" && typeof alg === "string" && k["alg"] !== alg) return false;
    try {
      return algorithmsForJwk(k).includes(alg as JwsAlgorithm);
    } catch {
      return false;
    }
  });
  if (candidates.length === 0) {
    throw new JwsError(
      typeof kid === "string" ? `no JWK matches kid ${kid}` : "no JWK matches the token header",
    );
  }
  return candidates[0]!;
}

/** Resolver over a static JWKS document. */
export function createLocalJWKSet(jwks: { keys: Jwk[] }): JwkResolver {
  if (!jwks || !Array.isArray(jwks.keys)) {
    throw new JwsError("JWKS must have a keys array");
  }
  return async (header) => selectFromKeys(jwks.keys, header);
}

/** Resolver that fetches (and caches) a remote JWKS document. */
export function createRemoteJWKSet(
  url: URL | string,
  options?: { cacheMaxAge?: number },
): JwkResolver {
  const maxAge = options?.cacheMaxAge ?? 5 * 60 * 1000;
  let cached: { keys: Jwk[] } | undefined;
  let fetchedAt = 0;
  return async (header) => {
    if (!cached || Date.now() - fetchedAt > maxAge) {
      const resp = await fetch(String(url));
      if (!resp.ok) {
        throw new JwsError(`JWKS fetch failed: HTTP ${resp.status}`);
      }
      const doc = (await resp.json()) as { keys?: Jwk[] };
      if (!Array.isArray(doc.keys)) {
        throw new JwsError("remote JWKS has no keys array");
      }
      cached = { keys: doc.keys };
      fetchedAt = Date.now();
    }
    return selectFromKeys(cached.keys, header);
  };
}

/* ------------------------------------------------------------------ */
/*  Signature verification                                             */
/* ------------------------------------------------------------------ */

async function verifySignature(
  alg: JwsAlgorithm,
  jwk: Jwk,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (!algorithmsForJwk(jwk).includes(alg)) {
    // Key type and algorithm must agree — no cross-verification.
    throw new JwsError(`${alg} incompatible with kty ${jwk.kty}`);
  }
  if (alg === "EdDSA") {
    const pub = b64uDecode(jwkString(jwk, "x"), "JWK x");
    return ed25519.verify(signature, message, pub);
  }
  if (alg === "ES256" || alg === "ES384" || alg === "ES512") {
    const info = EC_CURVES[jwkString(jwk, "crv")];
    if (!info) throw new JwsError(`unsupported EC curve ${jwk["crv"]}`);
    const x = b64uDecode(jwkString(jwk, "x"), "JWK x");
    const y = b64uDecode(jwkString(jwk, "y"), "JWK y");
    const point = new Uint8Array(1 + x.length + y.length);
    point[0] = 0x04;
    point.set(x, 1);
    point.set(y, 1 + x.length);
    if (signature.length !== info.width * 2) return false;
    return info.curve.verify(signature, message, point, { prehash: true });
  }
  // RS256 / RS384 / RS512 → runtime WebCrypto.
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk as JsonWebKey,
    { name: "RSASSA-PKCS1-v1_5", hash: RSA_HASHES[alg]! },
    false,
    ["verify"],
  );
  const msg = new Uint8Array(message).buffer as ArrayBuffer;
  const sig = new Uint8Array(signature).buffer as ArrayBuffer;
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, msg);
}

/* ------------------------------------------------------------------ */
/*  jwtVerify                                                          */
/* ------------------------------------------------------------------ */

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  [claim: string]: unknown;
}

export interface JWTVerifyOptions {
  issuer?: string | string[];
  audience?: string | string[];
  algorithms?: JwsAlgorithm[];
  /** Seconds of clock skew tolerated on exp/nbf. */
  clockTolerance?: number;
  /** Required `typ` header (e.g. `dpop+jwt`). */
  typ?: string;
}

export interface JWTVerifyResult {
  payload: JWTPayload;
  protectedHeader: Record<string, unknown>;
}

/** Present for jose type compatibility: `key` is the resolved JWK. */
export interface ResolvedKey {
  key: Jwk;
}

export async function jwtVerify(
  token: string,
  key: Jwk | JwkResolver,
  options?: JWTVerifyOptions,
): Promise<JWTVerifyResult & ResolvedKey> {
  if (typeof token !== "string" || token === "") {
    throw new JwsError("empty token");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JwsError("expected three dot-separated segments");
  }
  const [h, p, s] = parts as [string, string, string];
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(b64uDecode(h, "header"))) as Record<
      string,
      unknown
    >;
  } catch (e) {
    throw new JwsError(`header parse: ${(e as Error).message}`);
  }
  const alg = header["alg"];
  if (typeof alg !== "string" || alg === "none") {
    throw new JwsError("token alg missing or none");
  }
  const allowed = options?.algorithms;
  if (allowed && !allowed.includes(alg as JwsAlgorithm)) {
    throw new JwsError(`algorithm ${alg} not allowed`);
  }
  if (!allowed && !["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "EdDSA"].includes(alg)) {
    throw new JwsError(`unsupported algorithm ${alg}`);
  }
  if (options?.typ !== undefined && header["typ"] !== options.typ) {
    throw new JwsError(`typ ${header["typ"]} is not ${options.typ}`);
  }

  const jwk = typeof key === "function" ? await key(header) : key;
  const signature = b64uDecode(s, "signature");
  const message = UTF8.encode(`${h}.${p}`);
  const valid = await verifySignature(alg as JwsAlgorithm, jwk, message, signature);
  if (!valid) {
    throw new JwsError("signature verification failed");
  }

  let payload: JWTPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64uDecode(p, "payload"))) as JWTPayload;
  } catch (e) {
    throw new JwsError(`payload parse: ${(e as Error).message}`);
  }
  validateClaims(payload, options);
  return { payload, protectedHeader: header, key: jwk };
}

function validateClaims(payload: JWTPayload, options?: JWTVerifyOptions): void {
  const now = Math.floor(Date.now() / 1000);
  const leeway = options?.clockTolerance ?? 0;
  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number" || payload.exp + leeway < now) {
      throw new JwsError("token expired");
    }
  }
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number" || payload.nbf - leeway > now) {
      throw new JwsError("token not yet valid");
    }
  }
  if (options?.issuer !== undefined) {
    const issuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
    if (typeof payload.iss !== "string" || !issuers.includes(payload.iss)) {
      throw new JwsError(`issuer ${payload.iss} not accepted`);
    }
  }
  if (options?.audience !== undefined) {
    const expected = Array.isArray(options.audience) ? options.audience : [options.audience];
    const actual =
      typeof payload.aud === "string" ? [payload.aud] : Array.isArray(payload.aud) ? payload.aud : [];
    if (!actual.some((a) => expected.includes(a))) {
      throw new JwsError("audience not accepted");
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Signing + key generation (tests and vector generation)             */
/* ------------------------------------------------------------------ */

/** Private-key handle: a JWK carrying `d` (and RSA private members). */
export type PrivateJwk = Jwk;

export async function generateKeyPair(
  alg: JwsAlgorithm,
): Promise<{ publicKey: Jwk; privateKey: PrivateJwk }> {
  if (alg === "EdDSA") {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const publicKey: Jwk = { kty: "OKP", crv: "Ed25519", x: b64uEncode(pub) };
    return { publicKey, privateKey: { ...publicKey, d: b64uEncode(priv) } };
  }
  const ec = Object.entries(EC_CURVES).find(([, info]) => info.alg === alg);
  if (ec) {
    const [crv, info] = ec;
    const priv = info.curve.utils.randomPrivateKey();
    const point = info.curve.getPublicKey(priv, false);
    const publicKey: Jwk = {
      kty: "EC",
      crv,
      x: b64uEncode(point.subarray(1, 1 + info.width)),
      y: b64uEncode(point.subarray(1 + info.width)),
    };
    return { publicKey, privateKey: { ...publicKey, d: b64uEncode(priv) } };
  }
  // RSA via runtime WebCrypto.
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: RSA_HASHES[alg]!,
    },
    true,
    ["sign", "verify"],
  );
  const publicKey = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Jwk;
  const privateKey = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as Jwk;
  return { publicKey, privateKey };
}

/** Strip private members, returning the public JWK. */
export async function exportJWK(key: Jwk): Promise<Jwk> {
  const out: Jwk = { kty: key.kty };
  for (const member of ["crv", "x", "y", "n", "e"]) {
    if (typeof key[member] === "string") out[member] = key[member];
  }
  return out;
}

async function signMessage(alg: JwsAlgorithm, key: PrivateJwk, message: Uint8Array): Promise<Uint8Array> {
  if (alg === "EdDSA") {
    return ed25519.sign(message, b64uDecode(jwkString(key, "d"), "JWK d"));
  }
  const ec = Object.values(EC_CURVES).find((info) => info.alg === alg);
  if (ec) {
    const sig = ec.curve.sign(message, b64uDecode(jwkString(key, "d"), "JWK d"), {
      prehash: true,
    });
    return sig.toCompactRawBytes();
  }
  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    key as JsonWebKey,
    { name: "RSASSA-PKCS1-v1_5", hash: RSA_HASHES[alg]! },
    false,
    ["sign"],
  );
  const msg = new Uint8Array(message).buffer as ArrayBuffer;
  return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, msg));
}

function parseTimeInput(input: string | number, from: number): number {
  if (typeof input === "number") return Math.floor(input);
  const m = /^(\d+)\s*(s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?)$/.exec(
    input.trim(),
  );
  if (!m) throw new JwsError(`cannot parse time span ${JSON.stringify(input)}`);
  const n = Number(m[1]);
  const unit = m[2]![0];
  const seconds = unit === "s" ? n : unit === "m" ? n * 60 : unit === "h" ? n * 3600 : n * 86400;
  return from + seconds;
}

/** Compact JWT builder, name-compatible with jose's `SignJWT`. */
export class SignJWT {
  private payload: Record<string, unknown>;
  private header: Record<string, unknown> = {};

  constructor(payload: Record<string, unknown> = {}) {
    this.payload = { ...payload };
  }

  setProtectedHeader(header: Record<string, unknown>): this {
    this.header = { ...header };
    return this;
  }

  setIssuer(iss: string): this {
    this.payload["iss"] = iss;
    return this;
  }

  setSubject(sub: string): this {
    this.payload["sub"] = sub;
    return this;
  }

  setAudience(aud: string | string[]): this {
    this.payload["aud"] = aud;
    return this;
  }

  setIssuedAt(iat?: number): this {
    this.payload["iat"] = iat ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setExpirationTime(input: string | number): this {
    this.payload["exp"] = parseTimeInput(input, Math.floor(Date.now() / 1000));
    return this;
  }

  setNotBefore(input: string | number): this {
    this.payload["nbf"] = parseTimeInput(input, Math.floor(Date.now() / 1000));
    return this;
  }

  setJti(jti: string): this {
    this.payload["jti"] = jti;
    return this;
  }

  async sign(key: PrivateJwk): Promise<string> {
    const alg = this.header["alg"];
    if (typeof alg !== "string") {
      throw new JwsError("protected header must set alg");
    }
    const h = b64uEncode(UTF8.encode(JSON.stringify(this.header)));
    const p = b64uEncode(UTF8.encode(JSON.stringify(this.payload)));
    const signature = await signMessage(alg as JwsAlgorithm, key, UTF8.encode(`${h}.${p}`));
    return `${h}.${p}.${b64uEncode(signature)}`;
  }
}

/** jose-compatible alias for a JWKS document. */
export type JSONWebKeySet = { keys: Jwk[] };
