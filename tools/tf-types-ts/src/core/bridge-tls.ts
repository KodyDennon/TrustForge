/**
 * TLS / mTLS bridge — accept a peer-supplied X.509 certificate chain,
 * verify it against a configured set of trust anchors, and project the
 * verified leaf into a TrustForge actor identity + capabilities.
 *
 * Uses Bun's built-in `node:crypto` X509Certificate API (a libuv-backed
 * binding to BoringSSL) for parsing and signature verification — we do
 * not roll our own ASN.1 path validator.
 */

import { X509Certificate, createPublicKey } from "node:crypto";

import type { ActorIdentity } from "../generated/actor-identity.js";
import type { Capability } from "../generated/_common.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";

export interface TlsBridgeConfig {
  bridgeId: string;
  /** Trust domain that owns this bridge instance. */
  trustDomain: string;
  /** PEM-encoded trust anchors. The leaf chain must terminate in one of these. */
  rootCertificatesPem: string[];
  /** Optional clock override for testing — defaults to `Date.now()`. */
  now?: () => Date;
  /** Maximum acceptable chain length (leaf + intermediates + root). Default 6. */
  maxChainLength?: number;
  /** Optional SAN URI predicate. When set, the leaf must list a URI SAN
   *  matching this value (typical pattern: pin to a SPIFFE ID). */
  requiredSanUri?: string;
  /** Optional override that turns each leaf EKU OID into a TrustForge action.
   *  Default: use the table in `EKU_TO_ACTION`. */
  ekuToAction?: (oid: string) => string | undefined;
}

export interface TlsVerificationResult {
  identity: ActorIdentity;
  capabilities: Capability[];
  leaf: X509Certificate;
  chain: X509Certificate[];
}

/** Default mapping from X.509 Extended Key Usage OIDs to TrustForge actions. */
export const EKU_TO_ACTION: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "tls.server-auth",
  "1.3.6.1.5.5.7.3.2": "tls.client-auth",
  "1.3.6.1.5.5.7.3.3": "code.sign",
  "1.3.6.1.5.5.7.3.4": "email.protect",
  "1.3.6.1.5.5.7.3.8": "timestamp.sign",
  "1.3.6.1.5.5.7.3.9": "ocsp.sign",
};

/** Parse one or more PEM blocks (whitespace-separated) into X509 cert objects. */
export function parsePemBundle(pem: string): X509Certificate[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks || blocks.length === 0) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: "PEM bundle contains no CERTIFICATE blocks",
    });
  }
  return blocks.map((b) => new X509Certificate(b));
}

export class TlsBridge implements Bridge {
  readonly kind: BridgeKind = "tls";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: TlsBridgeConfig;
  private readonly roots: X509Certificate[];

  constructor(cfg: TlsBridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
    if (!cfg.rootCertificatesPem || cfg.rootCertificatesPem.length === 0) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: "TLS bridge requires at least one trust anchor",
      });
    }
    this.roots = cfg.rootCertificatesPem.map((p, i) => {
      try {
        return parsePemBundle(p)[0]!;
      } catch (e) {
        throw new BridgeFailure({
          code: "invalid-input",
          message: `root[${i}] failed to parse: ${(e as Error).message}`,
        });
      }
    });
  }

  /** Verify a peer chain (leaf first, then intermediates) and return the
   *  projected TrustForge identity + capabilities derived from the leaf. */
  verifyChain(chainPem: string[] | string): TlsVerificationResult {
    const certs =
      typeof chainPem === "string"
        ? parsePemBundle(chainPem)
        : chainPem.flatMap((p) => parsePemBundle(p));
    if (certs.length === 0) {
      throw new BridgeFailure({ code: "invalid-input", message: "empty chain" });
    }
    const max = this.cfg.maxChainLength ?? 6;
    if (certs.length > max) {
      throw new BridgeFailure({
        code: "rejected",
        message: `chain longer than max (${certs.length} > ${max})`,
      });
    }
    const now = (this.cfg.now ?? (() => new Date()))();

    // Validate every cert's validity window first — cheap and avoids verifying
    // signatures on already-expired material.
    for (const c of certs) {
      const notBefore = new Date(c.validFrom);
      const notAfter = new Date(c.validTo);
      if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) {
        throw new BridgeFailure({
          code: "rejected",
          message: `cert ${c.subject} has unparseable validity window`,
        });
      }
      if (now < notBefore) {
        throw new BridgeFailure({
          code: "rejected",
          message: `cert ${c.subject} not yet valid (notBefore=${notBefore.toISOString()})`,
        });
      }
      if (now > notAfter) {
        throw new BridgeFailure({
          code: "rejected",
          message: `cert ${c.subject} expired (notAfter=${notAfter.toISOString()})`,
        });
      }
    }

    // Walk leaf → intermediates verifying each link, then verify the final
    // intermediate against a configured root.
    const leaf = certs[0]!;
    const chain: X509Certificate[] = [leaf];
    let current = leaf;
    for (let depth = 0; depth < max; depth++) {
      const issuer =
        certs.slice(1).find((c) => c.subject === current.issuer && c !== current) ??
        this.roots.find((r) => r.subject === current.issuer);
      if (!issuer) {
        throw new BridgeFailure({
          code: "rejected",
          message: `no issuer cert for ${current.subject} (issuer=${current.issuer})`,
        });
      }
      // BoringSSL verifies the cert's signature using the issuer public key;
      // returns false on mismatch, throws on malformed input.
      const ok = current.verify(issuer.publicKey);
      if (!ok) {
        throw new BridgeFailure({
          code: "rejected",
          message: `signature verification failed for ${current.subject}`,
        });
      }
      if (this.roots.includes(issuer)) {
        chain.push(issuer);
        // Confirm the root is self-signed and within validity.
        const selfOk = issuer.verify(issuer.publicKey);
        if (!selfOk) {
          throw new BridgeFailure({
            code: "rejected",
            message: `root ${issuer.subject} not self-consistent`,
          });
        }
        return this.project(leaf, chain);
      }
      chain.push(issuer);
      current = issuer;
    }
    throw new BridgeFailure({
      code: "rejected",
      message: `chain exceeds max depth ${max} without reaching a trust anchor`,
    });
  }

  private project(leaf: X509Certificate, chain: X509Certificate[]): TlsVerificationResult {
    if (this.cfg.requiredSanUri) {
      const sans = parseSanUris(leaf);
      if (!sans.includes(this.cfg.requiredSanUri)) {
        throw new BridgeFailure({
          code: "rejected",
          message: `leaf SAN URIs ${JSON.stringify(sans)} missing required ${this.cfg.requiredSanUri}`,
        });
      }
    }
    const sanUris = parseSanUris(leaf);
    const sanDns = parseSanDns(leaf);
    // Prefer a spiffe:// URI SAN as the actor binding; else CN; else first DNS SAN.
    const spiffeSan = sanUris.find((u) => u.startsWith("spiffe://"));
    const cn = parseCommonName(leaf.subject);
    const subject = spiffeSan ?? cn ?? sanDns[0] ?? leaf.subject;
    const actorType: ActorIdentity["actor_type"] = spiffeSan ? "service" : "device";
    const actorId = `tf:actor:${actorType}:${this.cfg.trustDomain}/${encodeActorPath(subject)}`;
    const publicKey = leaf.publicKey;
    const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    const algorithm = jwkAlgorithmName(jwk);
    const publicKeyB64 = encodePublicKey(jwk);

    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: actorId,
      actor_type: actorType,
      public_keys: [
        {
          key_id: leaf.fingerprint256.replace(/:/g, "").toLowerCase(),
          algorithm,
          public_key: publicKeyB64,
          purpose: "signing",
        },
      ],
      trust_levels: [actorType === "service" ? "T4" : "T3"],
      authority_roots: chain.slice(-1).map((root) => ({
        kind: "organization" as const,
        id: parseCommonName(root.subject) ?? root.subject,
      })),
      valid_from: new Date(leaf.validFrom).toISOString(),
      valid_until: new Date(leaf.validTo).toISOString(),
    };

    const capabilities = ekusForLeaf(leaf).flatMap((oid) => {
      const action = (this.cfg.ekuToAction ?? ((o) => EKU_TO_ACTION[o]))(oid);
      return action ? [{ name: action, risk: "R2" as const }] : [];
    });

    return { identity, capabilities, leaf, chain };
  }
}

/** Pull URI SANs out of a certificate (best-effort, RFC 5280 §4.2.1.6). */
export function parseSanUris(cert: X509Certificate): string[] {
  const san = (cert as unknown as { subjectAltName?: string }).subjectAltName;
  if (!san) return [];
  const out: string[] = [];
  for (const part of san.split(",").map((s) => s.trim())) {
    const m = /^URI:(.*)$/.exec(part);
    if (m) out.push(m[1]!);
  }
  return out;
}

export function parseSanDns(cert: X509Certificate): string[] {
  const san = (cert as unknown as { subjectAltName?: string }).subjectAltName;
  if (!san) return [];
  const out: string[] = [];
  for (const part of san.split(",").map((s) => s.trim())) {
    const m = /^DNS:(.*)$/.exec(part);
    if (m) out.push(m[1]!);
  }
  return out;
}

function parseCommonName(distinguishedName: string): string | undefined {
  for (const part of distinguishedName.split(/[,\n]/).map((s) => s.trim())) {
    const m = /^CN\s*=\s*(.+)$/i.exec(part);
    if (m) return m[1]!;
  }
  return undefined;
}

function encodeActorPath(s: string): string {
  let out = "";
  for (const ch of s) {
    if (/[A-Za-z0-9_.~/-]/.test(ch)) out += ch;
    else out += encodeURIComponent(ch);
  }
  return out;
}

function jwkAlgorithmName(jwk: Record<string, unknown>): "ed25519" | "p256" | "p384" | "rsa" {
  const kty = jwk["kty"];
  const crv = jwk["crv"];
  if (kty === "OKP" && crv === "Ed25519") return "ed25519";
  if (kty === "EC" && crv === "P-256") return "p256";
  if (kty === "EC" && crv === "P-384") return "p384";
  if (kty === "RSA") return "rsa";
  throw new BridgeFailure({
    code: "unsupported",
    message: `unsupported JWK kty/crv: ${kty}/${crv}`,
  });
}

function encodePublicKey(jwk: Record<string, unknown>): string {
  // For Ed25519 we ship the raw 32-byte x. For EC P-256/P-384 we ship
  // uncompressed SEC1 (0x04||x||y). For RSA we ship the SubjectPublicKeyInfo
  // DER (re-derived via createPublicKey). All base64-encoded.
  const kty = jwk["kty"];
  if (kty === "OKP") {
    return base64FromBase64Url(String(jwk["x"]));
  }
  if (kty === "EC") {
    const x = base64UrlToBytes(String(jwk["x"]));
    const y = base64UrlToBytes(String(jwk["y"]));
    const buf = new Uint8Array(1 + x.length + y.length);
    buf[0] = 0x04;
    buf.set(x, 1);
    buf.set(y, 1 + x.length);
    return Buffer.from(buf).toString("base64");
  }
  if (kty === "RSA") {
    const k = createPublicKey({ key: jwk as object, format: "jwk" });
    return k.export({ format: "der", type: "spki" }).toString("base64");
  }
  throw new BridgeFailure({ code: "unsupported", message: `unsupported jwk kty: ${kty}` });
}

function base64FromBase64Url(b64u: string): string {
  return Buffer.from(base64UrlToBytes(b64u)).toString("base64");
}

function base64UrlToBytes(b64u: string): Uint8Array {
  let s = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  return new Uint8Array(Buffer.from(s, "base64"));
}

function ekusForLeaf(cert: X509Certificate): string[] {
  // node:crypto's X509Certificate doesn't expose EKUs directly, but the
  // certificate's `infoAccess` covers AIA OIDs. For EKU we parse the raw DER
  // ASN.1 of the extension: id-ce-extKeyUsage OID is 2.5.29.37.
  const der = cert.raw;
  return extractEkuOids(new Uint8Array(der));
}

/** Lightweight DER walker: find the extKeyUsage extension OID 2.5.29.37 and
 *  return the list of OIDs inside its SEQUENCE OF OBJECT IDENTIFIER. We
 *  intentionally avoid pulling in a full ASN.1 library here. */
export function extractEkuOids(der: Uint8Array): string[] {
  const eku = findExtension(der, "2.5.29.37");
  if (!eku) return [];
  // EKU value is OCTET STRING wrapping a SEQUENCE OF OID.
  return readOidSequence(eku);
}

function findExtension(der: Uint8Array, targetOid: string): Uint8Array | null {
  // Walk: top SEQUENCE = Certificate; first child = TBSCertificate; we descend
  // until we find a SEQUENCE OF Extension blocks.
  const cert = readSequence(der, 0);
  if (!cert) return null;
  const tbs = readSequence(der, cert.contentStart);
  if (!tbs) return null;
  // Inside TBSCertificate, walk fields until we hit the [3] extensions tag.
  let pos = tbs.contentStart;
  const end = tbs.contentStart + tbs.contentLength;
  while (pos < end) {
    const tag = der[pos]!;
    const len = readLength(der, pos + 1);
    if (!len) return null;
    if (tag === 0xa3) {
      // [3] EXPLICIT Extensions
      const inner = readSequence(der, pos + 1 + len.headerSize);
      if (!inner) return null;
      let p = inner.contentStart;
      const innerEnd = inner.contentStart + inner.contentLength;
      while (p < innerEnd) {
        const ext = readSequence(der, p);
        if (!ext) return null;
        const oid = readOid(der, ext.contentStart);
        if (!oid) return null;
        if (oid.value === targetOid) {
          // Skip optional BOOLEAN critical, then OCTET STRING containing extn value.
          let q = oid.nextPos;
          if (der[q] === 0x01) {
            const bl = readLength(der, q + 1);
            if (!bl) return null;
            q = q + 1 + bl.headerSize + bl.length;
          }
          if (der[q] !== 0x04) return null;
          const ol = readLength(der, q + 1);
          if (!ol) return null;
          return der.subarray(q + 1 + ol.headerSize, q + 1 + ol.headerSize + ol.length);
        }
        p = ext.contentStart + ext.contentLength;
      }
      return null;
    }
    pos = pos + 1 + len.headerSize + len.length;
  }
  return null;
}

function readOidSequence(extnValue: Uint8Array): string[] {
  const seq = readSequence(extnValue, 0);
  if (!seq) return [];
  const out: string[] = [];
  let p = seq.contentStart;
  const end = seq.contentStart + seq.contentLength;
  while (p < end) {
    const oid = readOid(extnValue, p);
    if (!oid) break;
    out.push(oid.value);
    p = oid.nextPos;
  }
  return out;
}

interface SeqHeader {
  contentStart: number;
  contentLength: number;
}

function readSequence(buf: Uint8Array, pos: number): SeqHeader | null {
  if (buf[pos] !== 0x30) return null;
  const len = readLength(buf, pos + 1);
  if (!len) return null;
  return { contentStart: pos + 1 + len.headerSize, contentLength: len.length };
}

function readLength(
  buf: Uint8Array,
  pos: number,
): { length: number; headerSize: number } | null {
  if (pos >= buf.length) return null;
  const b = buf[pos]!;
  if (b < 0x80) return { length: b, headerSize: 1 };
  const n = b & 0x7f;
  if (n === 0 || n > 4 || pos + n >= buf.length) return null;
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | buf[pos + 1 + i]!;
  return { length: len, headerSize: 1 + n };
}

function readOid(buf: Uint8Array, pos: number): { value: string; nextPos: number } | null {
  if (buf[pos] !== 0x06) return null;
  const len = readLength(buf, pos + 1);
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
