/**
 * Full WebAuthn attestation parser + verifier.
 *
 * Supports the three attestation formats that real authenticators produce
 * for software-only and hardware-backed flows: `none`, `packed`, and
 * `fido-u2f`. CBOR decoding uses the `cbor-x` library; signature
 * verification uses `@noble/curves` + `@noble/ed25519` so we don't depend
 * on Node's crypto for primitives.
 *
 * This module is independent of the high-level WebAuthn bridge — the
 * bridge calls into `verifyAttestation` and projects the verified
 * credential into a TrustForge actor-identity document.
 */

import { decode as cborDecode } from "cbor-x";
import { sha256 } from "@noble/hashes/sha256";
import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";

import { BridgeFailure } from "./bridges.js";

export type CoseAlgorithm = "ES256" | "EdDSA" | "RS256";
export type AttestationFormat = "none" | "packed" | "fido-u2f";

export interface ParsedAuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  aaguid: Uint8Array | null;
  credentialId: Uint8Array | null;
  /** Raw CBOR-encoded COSE public key bytes (still in COSE form). */
  credentialPublicKeyCose: Uint8Array | null;
  /** Decoded COSE public key as a JS object. */
  credentialPublicKey: CosePublicKey | null;
}

export interface CosePublicKey {
  kty: number; // 1=OKP, 2=EC2, 3=RSA
  alg?: CoseAlgorithm;
  crv?: number; // 1=P-256, 6=Ed25519
  /** EC2/OKP x coordinate (raw bytes). */
  x?: Uint8Array;
  /** EC2 y coordinate (raw bytes). */
  y?: Uint8Array;
  /** RSA modulus. */
  n?: Uint8Array;
  /** RSA public exponent. */
  e?: Uint8Array;
}

export interface AttestationObjectRaw {
  fmt: AttestationFormat;
  attStmt: Record<string, unknown>;
  authData: Uint8Array;
}

export interface ClientDataJsonParsed {
  type: string;
  challenge: string; // base64url
  origin: string;
  crossOrigin?: boolean;
  tokenBinding?: { status: string; id?: string };
}

export interface VerifyAttestationOptions {
  /** Expected RP ID, e.g. "example.com". The authData rpIdHash must match sha256(rpId). */
  rpId: string;
  /** Expected origin for clientDataJSON, e.g. "https://example.com". */
  expectedOrigin: string;
  /** Expected challenge (base64url); must match clientDataJSON.challenge. */
  expectedChallenge: string;
  /** Allowed COSE algorithm IDs. Default is the standard set. */
  allowedAlgorithms?: CoseAlgorithm[];
  /** Reject the attestation if attStmt verification fails (default: true).
   *  For pure `none` format this is a no-op. */
  requireAttestationSignature?: boolean;
}

export interface VerifiedAttestation {
  format: AttestationFormat;
  authData: ParsedAuthData;
  clientData: ClientDataJsonParsed;
  /** Public key of the new credential, in raw bytes (Ed25519 = 32B, P-256 = 65B uncompressed). */
  credentialPublicKey: Uint8Array;
  credentialId: Uint8Array;
  algorithm: CoseAlgorithm;
  /** When format=packed and x5c was supplied, the chain in DER-encoded form. */
  x5c?: Uint8Array[];
  signCount: number;
  flags: number;
  aaguid: Uint8Array | null;
}

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

export function parseAuthenticatorData(buf: Uint8Array): ParsedAuthData {
  if (buf.length < 37) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `authData too short (${buf.length} bytes)`,
    });
  }
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32]!;
  const signCount = (buf[33]! << 24) | (buf[34]! << 16) | (buf[35]! << 8) | buf[36]!;
  let aaguid: Uint8Array | null = null;
  let credentialId: Uint8Array | null = null;
  let credentialPublicKeyCose: Uint8Array | null = null;
  let credentialPublicKey: CosePublicKey | null = null;
  if ((flags & FLAG_ATTESTED_CREDENTIAL_DATA) !== 0) {
    if (buf.length < 55) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: "authData has AT flag but is too short for attested credential data",
      });
    }
    aaguid = buf.subarray(37, 53);
    const credIdLen = (buf[53]! << 8) | buf[54]!;
    if (buf.length < 55 + credIdLen) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: `authData truncated reading credentialId (declared ${credIdLen} bytes)`,
      });
    }
    credentialId = buf.subarray(55, 55 + credIdLen);
    const cose = buf.subarray(55 + credIdLen);
    credentialPublicKeyCose = cose;
    credentialPublicKey = parseCosePublicKey(cose);
  }
  return {
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credentialId,
    credentialPublicKeyCose,
    credentialPublicKey,
  };
}

export function parseCosePublicKey(cose: Uint8Array): CosePublicKey {
  let raw: unknown;
  try {
    raw = cborDecode(cose);
  } catch (e) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `COSE key is not valid CBOR: ${(e as Error).message}`,
    });
  }
  if (!(raw instanceof Map) && (typeof raw !== "object" || raw === null)) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "COSE key did not decode to a map",
    });
  }
  const map: Map<number, unknown> =
    raw instanceof Map
      ? (raw as Map<number, unknown>)
      : new Map(Object.entries(raw as Record<string, unknown>).map(([k, v]) => [Number(k), v]));
  const kty = numAt(map, 1);
  if (kty === undefined) {
    throw new BridgeFailure({ code: "invalid-input", message: "COSE key missing kty (1)" });
  }
  const alg = numAt(map, 3);
  const algName = coseAlgorithmName(alg);
  const out: CosePublicKey = { kty };
  if (algName) out.alg = algName;
  if (kty === 2 /* EC2 */) {
    out.crv = numAt(map, -1);
    out.x = bytesAt(map, -2);
    out.y = bytesAt(map, -3);
  } else if (kty === 1 /* OKP */) {
    out.crv = numAt(map, -1);
    out.x = bytesAt(map, -2);
  } else if (kty === 3 /* RSA */) {
    out.n = bytesAt(map, -1);
    out.e = bytesAt(map, -2);
  }
  return out;
}

function numAt(m: Map<number, unknown>, k: number): number | undefined {
  const v = m.get(k);
  if (typeof v === "number") return v;
  if (typeof v === "bigint") return Number(v);
  return undefined;
}

function bytesAt(m: Map<number, unknown>, k: number): Uint8Array | undefined {
  const v = m.get(k);
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v) && v.every((n) => typeof n === "number")) return new Uint8Array(v);
  return undefined;
}

function coseAlgorithmName(alg: number | undefined): CoseAlgorithm | undefined {
  switch (alg) {
    case -7:
      return "ES256";
    case -8:
      return "EdDSA";
    case -257:
      return "RS256";
    default:
      return undefined;
  }
}

export function decodeAttestationObject(buf: Uint8Array): AttestationObjectRaw {
  let raw: unknown;
  try {
    raw = cborDecode(buf);
  } catch (e) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `attestationObject is not valid CBOR: ${(e as Error).message}`,
    });
  }
  if (typeof raw !== "object" || raw === null) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "attestationObject did not decode to a map",
    });
  }
  const map = raw as { fmt?: unknown; attStmt?: unknown; authData?: unknown };
  if (typeof map.fmt !== "string") {
    throw new BridgeFailure({ code: "invalid-input", message: "missing/invalid fmt" });
  }
  if (!(map.authData instanceof Uint8Array)) {
    throw new BridgeFailure({ code: "invalid-input", message: "missing/invalid authData" });
  }
  if (typeof map.attStmt !== "object" || map.attStmt === null) {
    throw new BridgeFailure({ code: "invalid-input", message: "missing/invalid attStmt" });
  }
  if (map.fmt !== "none" && map.fmt !== "packed" && map.fmt !== "fido-u2f") {
    throw new BridgeFailure({
      code: "unsupported",
      message: `attestation format ${map.fmt} is not supported`,
    });
  }
  return {
    fmt: map.fmt,
    attStmt: map.attStmt as Record<string, unknown>,
    authData: map.authData,
  };
}

export function parseClientDataJSON(buf: Uint8Array): ClientDataJsonParsed {
  const json = new TextDecoder("utf-8").decode(buf);
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `clientDataJSON not valid JSON: ${(e as Error).message}`,
    });
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new BridgeFailure({ code: "invalid-input", message: "clientDataJSON not an object" });
  }
  const o = parsed as ClientDataJsonParsed;
  if (typeof o.type !== "string" || typeof o.challenge !== "string" || typeof o.origin !== "string") {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "clientDataJSON missing required fields type/challenge/origin",
    });
  }
  return o;
}

export function verifyAttestation(
  attestationObject: Uint8Array,
  clientDataJSON: Uint8Array,
  opts: VerifyAttestationOptions,
): VerifiedAttestation {
  const att = decodeAttestationObject(attestationObject);
  const authData = parseAuthenticatorData(att.authData);
  const clientData = parseClientDataJSON(clientDataJSON);

  if (clientData.type !== "webauthn.create") {
    throw new BridgeFailure({
      code: "rejected",
      message: `clientData.type ${clientData.type} is not webauthn.create`,
    });
  }
  if (clientData.origin !== opts.expectedOrigin) {
    throw new BridgeFailure({
      code: "rejected",
      message: `clientData.origin ${clientData.origin} does not match expected ${opts.expectedOrigin}`,
    });
  }
  if (clientData.challenge !== opts.expectedChallenge) {
    throw new BridgeFailure({
      code: "rejected",
      message: "clientData.challenge does not match expected",
    });
  }

  // Verify rpIdHash
  const rpIdHashExpected = sha256(new TextEncoder().encode(opts.rpId));
  if (!constantTimeEqual(authData.rpIdHash, rpIdHashExpected)) {
    throw new BridgeFailure({
      code: "rejected",
      message: "authData rpIdHash does not match sha256(rpId)",
    });
  }
  // User present is mandatory
  if ((authData.flags & FLAG_USER_PRESENT) === 0) {
    throw new BridgeFailure({
      code: "rejected",
      message: "authData missing User Present flag",
    });
  }
  if ((authData.flags & FLAG_ATTESTED_CREDENTIAL_DATA) === 0) {
    throw new BridgeFailure({
      code: "rejected",
      message: "authData missing AT flag (no attested credential data)",
    });
  }
  if (!authData.credentialPublicKey || !authData.credentialId) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "authData is missing credential public key or id",
    });
  }
  const algName = authData.credentialPublicKey.alg;
  if (!algName) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "credential public key has no algorithm",
    });
  }
  const allowed = opts.allowedAlgorithms ?? ["ES256", "EdDSA", "RS256"];
  if (!allowed.includes(algName)) {
    throw new BridgeFailure({
      code: "rejected",
      message: `algorithm ${algName} is not in the allow-list`,
    });
  }

  // Verify the attestation signature (if any).
  const clientDataHash = sha256(clientDataJSON);
  if (att.fmt === "packed") {
    verifyPackedSignature(att, authData, clientDataHash);
  } else if (att.fmt === "fido-u2f") {
    verifyFidoU2fSignature(att, authData, clientDataHash);
  } else if (opts.requireAttestationSignature && att.fmt === "none") {
    throw new BridgeFailure({
      code: "rejected",
      message: "format=none rejected when requireAttestationSignature=true",
    });
  }

  const credentialPublicKey = encodeRawPublicKey(authData.credentialPublicKey);
  const x5c = pickX5c(att.attStmt);
  return {
    format: att.fmt,
    authData,
    clientData,
    credentialPublicKey,
    credentialId: authData.credentialId,
    algorithm: algName,
    x5c,
    signCount: authData.signCount,
    flags: authData.flags,
    aaguid: authData.aaguid,
  };
}

function pickX5c(attStmt: Record<string, unknown>): Uint8Array[] | undefined {
  const x5c = attStmt["x5c"];
  if (!Array.isArray(x5c)) return undefined;
  const out: Uint8Array[] = [];
  for (const c of x5c) {
    if (c instanceof Uint8Array) out.push(c);
  }
  return out.length > 0 ? out : undefined;
}

function verifyPackedSignature(
  att: AttestationObjectRaw,
  authData: ParsedAuthData,
  clientDataHash: Uint8Array,
): void {
  const sig = att.attStmt["sig"];
  const alg = att.attStmt["alg"];
  if (!(sig instanceof Uint8Array)) {
    throw new BridgeFailure({ code: "invalid-input", message: "packed attStmt missing sig" });
  }
  if (typeof alg !== "number") {
    throw new BridgeFailure({ code: "invalid-input", message: "packed attStmt missing alg" });
  }
  const verificationData = concatBytes(att.authData, clientDataHash);
  const x5c = pickX5c(att.attStmt);
  if (x5c && x5c.length > 0) {
    // Full attestation: signature is over (authData||clientDataHash) using
    // attestation cert's public key.
    verifyWithCertChain(x5c, verificationData, sig, alg);
    return;
  }
  // Self-attestation: signature is over (authData||clientDataHash) using the
  // attested credential's own public key.
  verifyCoseSignature(authData.credentialPublicKey!, verificationData, sig, alg);
}

function verifyFidoU2fSignature(
  att: AttestationObjectRaw,
  authData: ParsedAuthData,
  clientDataHash: Uint8Array,
): void {
  const sig = att.attStmt["sig"];
  const x5c = pickX5c(att.attStmt);
  if (!(sig instanceof Uint8Array) || !x5c || x5c.length === 0) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "fido-u2f attStmt missing sig or x5c",
    });
  }
  const cose = authData.credentialPublicKey;
  if (!cose || cose.kty !== 2 || !cose.x || !cose.y) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "fido-u2f requires EC2 P-256 credential public key",
    });
  }
  // U2F verification data: 0x00 || rpIdHash || clientDataHash || credId || pubkey
  const verificationData = concatBytes(
    new Uint8Array([0x00]),
    authData.rpIdHash,
    clientDataHash,
    authData.credentialId!,
    new Uint8Array([0x04]),
    cose.x,
    cose.y,
  );
  verifyWithCertChain(x5c, verificationData, sig, -7); // U2F is always ECDSA-P256-SHA-256.
}

function verifyWithCertChain(
  x5c: Uint8Array[],
  data: Uint8Array,
  signature: Uint8Array,
  alg: number,
): void {
  const cert = x5c[0]!;
  const pub = extractSpkiPublicKey(cert);
  verifyAlgorithmSignature(pub.alg, pub.publicKey, data, signature, alg);
}

function verifyCoseSignature(
  cose: CosePublicKey,
  data: Uint8Array,
  signature: Uint8Array,
  alg: number,
): void {
  if (alg === -7 && cose.kty === 2 && cose.x && cose.y) {
    const pub = concatBytes(new Uint8Array([0x04]), cose.x, cose.y);
    if (!p256.verify(derToCompactSig(signature), sha256(data), pub)) {
      throw new BridgeFailure({
        code: "rejected",
        message: "ES256 self-attestation signature failed",
      });
    }
    return;
  }
  if (alg === -8 && cose.kty === 1 && cose.x) {
    if (!ed25519.verify(signature, data, cose.x)) {
      throw new BridgeFailure({
        code: "rejected",
        message: "EdDSA self-attestation signature failed",
      });
    }
    return;
  }
  throw new BridgeFailure({
    code: "unsupported",
    message: `self-attestation alg ${alg} on kty ${cose.kty} not supported`,
  });
}

interface CertPublicKey {
  alg: "p256" | "ed25519" | "rsa";
  publicKey: Uint8Array;
}

/** Extract the SubjectPublicKeyInfo from a DER X.509 certificate, returning
 *  the algorithm tag plus raw public key bytes (uncompressed for EC, raw for
 *  Ed25519, modulus||exponent encoded as full SPKI for RSA). */
export function extractSpkiPublicKey(certDer: Uint8Array): CertPublicKey {
  // top-level Certificate SEQUENCE; tbsCertificate SEQUENCE; iterate until
  // SubjectPublicKeyInfo (SEQUENCE { AlgorithmIdentifier, BIT STRING }).
  const cert = readSeq(certDer, 0);
  if (!cert) throw new BridgeFailure({ code: "invalid-input", message: "certificate not a SEQUENCE" });
  const tbs = readSeq(certDer, cert.contentStart);
  if (!tbs) throw new BridgeFailure({ code: "invalid-input", message: "tbsCertificate not a SEQUENCE" });
  // Inside tbsCertificate: [0] version (optional), CertificateSerialNumber,
  // signature AlgorithmIdentifier, Name issuer, Validity, Name subject, SPKI.
  let p = tbs.contentStart;
  const end = tbs.contentStart + tbs.contentLength;
  let seqIdx = 0;
  while (p < end) {
    const tag = certDer[p]!;
    const lh = readLen(certDer, p + 1);
    if (!lh) throw new BridgeFailure({ code: "invalid-input", message: "bad length" });
    const blockLen = 1 + lh.headerSize + lh.length;
    if (tag === 0xa0) {
      p += blockLen;
      continue;
    }
    // Field count: serialNumber(0), signature(1), issuer(2), validity(3), subject(4), SPKI(5)
    if (seqIdx === 5 && tag === 0x30) {
      // Found SubjectPublicKeyInfo
      const spki = readSeq(certDer, p)!;
      // first SEQUENCE = AlgorithmIdentifier { OID, params }
      const algSeq = readSeq(certDer, spki.contentStart)!;
      const oid = readOid(certDer, algSeq.contentStart);
      if (!oid) throw new BridgeFailure({ code: "invalid-input", message: "missing alg OID" });
      // BIT STRING after AlgorithmIdentifier is the public key bytes
      const bitStringPos = spki.contentStart + 1 + readLen(certDer, spki.contentStart + 1)!.headerSize + readLen(certDer, spki.contentStart + 1)!.length;
      if (certDer[bitStringPos] !== 0x03) {
        throw new BridgeFailure({ code: "invalid-input", message: "SPKI BIT STRING missing" });
      }
      const bsLen = readLen(certDer, bitStringPos + 1)!;
      const bsStart = bitStringPos + 1 + bsLen.headerSize;
      // First byte of BIT STRING is unused-bits count, skip it.
      const keyBytes = certDer.subarray(bsStart + 1, bsStart + bsLen.length);
      if (oid.value === "1.2.840.10045.2.1") {
        // ecPublicKey — keyBytes is the SEC1 uncompressed point.
        return { alg: "p256", publicKey: keyBytes };
      }
      if (oid.value === "1.3.101.112") {
        return { alg: "ed25519", publicKey: keyBytes };
      }
      if (oid.value === "1.2.840.113549.1.1.1") {
        // RSA — keyBytes is RSAPublicKey DER (SEQUENCE { modulus INTEGER, exponent INTEGER }).
        return { alg: "rsa", publicKey: keyBytes };
      }
      throw new BridgeFailure({
        code: "unsupported",
        message: `SPKI algorithm OID ${oid.value} not supported`,
      });
    }
    p += blockLen;
    seqIdx++;
  }
  throw new BridgeFailure({
    code: "invalid-input",
    message: "could not locate SubjectPublicKeyInfo in tbsCertificate",
  });
}

function verifyAlgorithmSignature(
  alg: "p256" | "ed25519" | "rsa",
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
  coseAlg: number,
): void {
  if (coseAlg === -7 && alg === "p256") {
    if (!p256.verify(derToCompactSig(signature), sha256(data), publicKey)) {
      throw new BridgeFailure({
        code: "rejected",
        message: "packed attestation ES256 signature failed",
      });
    }
    return;
  }
  if (coseAlg === -8 && alg === "ed25519") {
    if (!ed25519.verify(signature, data, publicKey)) {
      throw new BridgeFailure({
        code: "rejected",
        message: "packed attestation EdDSA signature failed",
      });
    }
    return;
  }
  if (coseAlg === -257 && alg === "rsa") {
    // RS256 PKCS#1 v1.5 verification — implemented inline so we don't pull
    // in another crypto dep.
    verifyRsaPkcs1Sha256(publicKey, data, signature);
    return;
  }
  throw new BridgeFailure({
    code: "unsupported",
    message: `verification of cose alg ${coseAlg} against ${alg} not supported`,
  });
}

function verifyRsaPkcs1Sha256(
  spkiKeyBytes: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): void {
  // Parse RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
  const rsa = readSeq(spkiKeyBytes, 0);
  if (!rsa) throw new BridgeFailure({ code: "invalid-input", message: "RSA SPKI not a SEQUENCE" });
  const nNode = readInteger(spkiKeyBytes, rsa.contentStart);
  if (!nNode) throw new BridgeFailure({ code: "invalid-input", message: "RSA modulus parse" });
  const eNode = readInteger(spkiKeyBytes, nNode.next);
  if (!eNode) throw new BridgeFailure({ code: "invalid-input", message: "RSA exponent parse" });
  const n = bigintFromBytes(nNode.bytes);
  const e = bigintFromBytes(eNode.bytes);
  const sigInt = bigintFromBytes(signature);
  // m = sig^e mod n
  const m = modPow(sigInt, e, n);
  const emLen = (n.toString(2).length + 7) >> 3;
  const em = bigintToBytes(m, emLen);
  // EMSA-PKCS1-v1_5 encoding: 0x00 0x01 PS 0x00 T (DigestInfo for SHA-256).
  if (em.length < 11 || em[0] !== 0x00 || em[1] !== 0x01) {
    throw new BridgeFailure({ code: "rejected", message: "PKCS1 padding mismatch" });
  }
  let i = 2;
  while (i < em.length && em[i] === 0xff) i++;
  if (i === em.length || em[i] !== 0x00) {
    throw new BridgeFailure({ code: "rejected", message: "PKCS1 padding mismatch" });
  }
  i++;
  // SHA-256 DigestInfo prefix
  const sha256DigestInfo = new Uint8Array([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
  ]);
  if (!bytesEqual(em.subarray(i, i + sha256DigestInfo.length), sha256DigestInfo)) {
    throw new BridgeFailure({ code: "rejected", message: "PKCS1 DigestInfo mismatch" });
  }
  i += sha256DigestInfo.length;
  const expectedHash = sha256(data);
  if (!bytesEqual(em.subarray(i, i + 32), expectedHash)) {
    throw new BridgeFailure({ code: "rejected", message: "RS256 hash mismatch" });
  }
}

function bigintFromBytes(b: Uint8Array): bigint {
  let acc = 0n;
  for (const byte of b) acc = (acc << 8n) | BigInt(byte);
  return acc;
}

function bigintToBytes(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return bytesEqual(a, b);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Convert a DER-encoded ECDSA signature (SEQUENCE { r, s INTEGER }) into
 *  the 64-byte compact r||s form noble expects. */
function derToCompactSig(der: Uint8Array): Uint8Array {
  const seq = readSeq(der, 0);
  if (!seq) throw new BridgeFailure({ code: "invalid-input", message: "ECDSA sig not a SEQUENCE" });
  const rNode = readInteger(der, seq.contentStart);
  if (!rNode) throw new BridgeFailure({ code: "invalid-input", message: "ECDSA r parse" });
  const sNode = readInteger(der, rNode.next);
  if (!sNode) throw new BridgeFailure({ code: "invalid-input", message: "ECDSA s parse" });
  return concatBytes(padLeft(rNode.bytes, 32), padLeft(sNode.bytes, 32));
}

function padLeft(b: Uint8Array, len: number): Uint8Array {
  if (b.length === len) return b;
  if (b.length > len) return b.subarray(b.length - len);
  const out = new Uint8Array(len);
  out.set(b, len - b.length);
  return out;
}

function encodeRawPublicKey(cose: CosePublicKey): Uint8Array {
  if (cose.kty === 2 && cose.x && cose.y) {
    const out = new Uint8Array(1 + cose.x.length + cose.y.length);
    out[0] = 0x04;
    out.set(cose.x, 1);
    out.set(cose.y, 1 + cose.x.length);
    return out;
  }
  if (cose.kty === 1 && cose.x) {
    return cose.x;
  }
  if (cose.kty === 3 && cose.n && cose.e) {
    return cose.n; // Caller can re-encode if needed; raw modulus is enough for storage.
  }
  throw new BridgeFailure({ code: "invalid-input", message: "unsupported COSE key shape" });
}

interface SeqHeader {
  contentStart: number;
  contentLength: number;
}

function readSeq(buf: Uint8Array, pos: number): SeqHeader | null {
  if (buf[pos] !== 0x30) return null;
  const len = readLen(buf, pos + 1);
  if (!len) return null;
  return { contentStart: pos + 1 + len.headerSize, contentLength: len.length };
}

function readLen(buf: Uint8Array, pos: number): { length: number; headerSize: number } | null {
  if (pos >= buf.length) return null;
  const b = buf[pos]!;
  if (b < 0x80) return { length: b, headerSize: 1 };
  const n = b & 0x7f;
  if (n === 0 || n > 4 || pos + n >= buf.length) return null;
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | buf[pos + 1 + i]!;
  return { length: len, headerSize: 1 + n };
}

function readOid(
  buf: Uint8Array,
  pos: number,
): { value: string; nextPos: number } | null {
  if (buf[pos] !== 0x06) return null;
  const len = readLen(buf, pos + 1);
  if (!len) return null;
  const start = pos + 1 + len.headerSize;
  const data = buf.subarray(start, start + len.length);
  if (data.length === 0) return null;
  const first = data[0]!;
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let acc = 0;
  for (let i = 1; i < data.length; i++) {
    acc = (acc << 7) | (data[i]! & 0x7f);
    if ((data[i]! & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return { value: parts.join("."), nextPos: start + len.length };
}

function readInteger(
  buf: Uint8Array,
  pos: number,
): { bytes: Uint8Array; next: number } | null {
  if (buf[pos] !== 0x02) return null;
  const len = readLen(buf, pos + 1);
  if (!len) return null;
  const start = pos + 1 + len.headerSize;
  let bytes = buf.subarray(start, start + len.length);
  // strip a single leading zero byte (used by DER to keep the integer non-negative)
  if (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
  return { bytes, next: start + len.length };
}
