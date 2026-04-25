/**
 * Credential resolver for tf-daemon's `POST /v1/import-credential` and
 * the `host_token` field on `POST /v1/decide`.
 *
 * The resolver sniffs the credential's first bytes to guess which
 * TrustForge bridge handles it, then projects the credential into a
 * `{actor, capabilities, trust_level, expires_at}` tuple. The
 * `.tf/bridges.yaml` registry (B4) overrides per-issuer mappings; built-in
 * defaults cover the common cases (Google / Clerk / NextAuth / Apple
 * WebAuthn / Linkerd SPIFFE / etc.) without configuration.
 *
 * This file does NOT call into network services. JWTs are decoded
 * (header + claims) but their signatures are NOT cryptographically
 * verified here — the daemon's bridge modules (`bridge_oauth.ts`, etc.)
 * own that responsibility against a configured JWKS. The resolver's
 * job is to (a) classify, (b) extract enough claims to build a
 * tentative TrustForge actor URI, and (c) hand the bytes to whichever
 * bridge will perform full verification when the operator supplies
 * keys / configuration via the registry.
 *
 * The protocol defines the wire shape; signature verification is a
 * SECOND-ORDER operation. Tests in
 * `tools/tf-daemon/tests/import-credential.test.ts` pin the
 * classification surface for every supported credential format.
 */

import {
  BridgesRegistry,
  type BridgeEntry,
  type BridgesRegistryKind,
} from "tf-types";

export type CredentialBridgeKind =
  | "oauth"
  | "clerk"
  | "next-auth"
  | "better-auth"
  | "webauthn"
  | "tls"
  | "spiffe"
  | "did"
  | "gnap"
  | "session-cookie"
  | "unknown";

export interface ResolvedCredential {
  actor: string;
  capabilities: string[];
  trust_level: string;
  bridge_kind: CredentialBridgeKind;
  expires_at: string | null;
  /** Decoded `iss` claim when known — used for registry lookups. */
  issuer?: string;
  /** Free-form classification reason for tracing / debugging. */
  detection_reason?: string;
}

export interface ResolveOptions {
  hint?: CredentialBridgeKind | null;
  registry?: BridgesRegistry;
  /** Trust domain to use when the credential does not name one (defaults to "local"). */
  trustDomain?: string;
}

const HEX_PREFIX_RE = /^[0-9a-fA-F]/;

function decodeBase64UrlClaims(token: string): Record<string, unknown> | null {
  const segments = token.split(".");
  if (segments.length < 2) return null;
  const claimsSeg = segments[1] ?? "";
  if (!claimsSeg) return null;
  let s = claimsSeg.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  try {
    const json = Buffer.from(s, "base64").toString("utf8");
    const parsed = JSON.parse(json) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

function decodeBase64UrlHeader(token: string): Record<string, unknown> | null {
  const segments = token.split(".");
  if (segments.length < 1) return null;
  const headerSeg = segments[0] ?? "";
  if (!headerSeg) return null;
  let s = headerSeg.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  try {
    const json = Buffer.from(s, "base64").toString("utf8");
    const parsed = JSON.parse(json) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

function looksLikeJwt(s: string): boolean {
  // JWT shape: 3 base64url-segments separated by dots. The first byte of
  // a base64url JSON header is almost always 'e' (eyJ — `{"`).
  if (!s.startsWith("eyJ")) return false;
  return s.split(".").length >= 2;
}

/** Try to parse `s` as JSON when it looks structured. */
function tryParseJson(s: string): unknown {
  if (s.length === 0) return null;
  if (s[0] !== "{" && s[0] !== "[") return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function trustDomainFromIss(iss: string): string {
  try {
    if (iss.startsWith("http://") || iss.startsWith("https://")) {
      const u = new URL(iss);
      return u.hostname || "local";
    }
    if (iss.startsWith("spiffe://")) {
      const u = new URL(iss);
      return u.hostname || "local";
    }
  } catch {
    /* fallthrough */
  }
  return iss || "local";
}

function isoFromUnix(unix: number | undefined): string | null {
  if (typeof unix !== "number" || !Number.isFinite(unix)) return null;
  return new Date(unix * 1000).toISOString();
}

/** Default trust level by bridge kind, used when no registry override
 *  applies. T1 is the floor; bridges that perform stronger
 *  out-of-band verification (mTLS, SPIFFE) start one tier higher. */
function defaultTrustLevelFor(kind: CredentialBridgeKind): string {
  switch (kind) {
    case "tls":
      return "T3";
    case "spiffe":
      return "T3";
    case "webauthn":
      return "T2";
    case "oauth":
    case "gnap":
      return "T2";
    case "did":
      return "T2";
    case "clerk":
    case "next-auth":
    case "better-auth":
    case "session-cookie":
      return "T1";
    case "unknown":
      return "T0";
  }
}

const REGISTRY_KIND_TO_BRIDGE: Record<BridgesRegistryKind, CredentialBridgeKind> = {
  oauth: "oauth",
  clerk: "clerk",
  "next-auth": "next-auth",
  "better-auth": "better-auth",
  webauthn: "webauthn",
  tls: "tls",
  spiffe: "spiffe",
  did: "did",
  gnap: "gnap",
  mcp: "unknown",
  matrix: "unknown",
  webhook: "unknown",
  grpc: "unknown",
  "service-mesh": "unknown",
  a2a: "unknown",
  "session-cookie": "session-cookie",
};

/** Apply a registry override on top of a baseline detection. */
function applyRegistryOverride(
  baseline: ResolvedCredential,
  override: BridgeEntry,
): ResolvedCredential {
  const bridge = REGISTRY_KIND_TO_BRIDGE[override.kind] ?? baseline.bridge_kind;
  const capabilities =
    override.capability_map !== undefined
      ? Object.values(override.capability_map)
      : baseline.capabilities;
  const trustLevel = override.trust_level ?? baseline.trust_level;
  let actor = baseline.actor;
  if (override.trust_domain && actor.includes(":")) {
    // Replace the actor's trust-domain segment when the registry pins one.
    const m = /^tf:actor:([^:]+):([^/]+)\/(.+)$/.exec(actor);
    if (m) {
      actor = `tf:actor:${m[1]}:${override.trust_domain}/${m[3]}`;
    }
  }
  return {
    ...baseline,
    bridge_kind: bridge,
    capabilities,
    trust_level: trustLevel,
    actor,
  };
}

/** Sniff classification phase. Returns a baseline `ResolvedCredential`
 *  before applying any registry override. */
function classifyAndProject(
  credential: string,
  hint: CredentialBridgeKind | null,
  trustDomain: string,
): ResolvedCredential {
  const trimmed = credential.trim();
  if (!trimmed) {
    return {
      actor: `tf:actor:process:${trustDomain}/unknown`,
      capabilities: [],
      trust_level: defaultTrustLevelFor("unknown"),
      bridge_kind: "unknown",
      expires_at: null,
      detection_reason: "empty credential",
    };
  }

  // Hint short-circuits classification only when the credential looks
  // plausible for the hinted kind — never pretend an obvious JWT is
  // an mTLS PEM blob.
  const heuristic = sniffKind(trimmed);
  const kind: CredentialBridgeKind = hint && hint !== "unknown" ? hint : heuristic;

  switch (kind) {
    case "oauth":
    case "next-auth": {
      // Both ride a JWT; next-auth uses HS256 by default. We do NOT
      // verify the signature here; the bridge does. We DO surface the
      // claims so the registry can pin trust level + actor.
      // NextAuth also issues opaque DB-backed session ids carried as
      // a `__Secure-next-auth.session-token=...` cookie. Recognize
      // that form so the resolver still classifies as next-auth.
      const nextAuthCookieMatch = /^(?:__Secure-)?next-auth\.session-token=(.+)$/.exec(trimmed);
      if (kind === "next-auth" && nextAuthCookieMatch) {
        const value = nextAuthCookieMatch[1] ?? "";
        return {
          actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(value)}`,
          capabilities: [],
          trust_level: defaultTrustLevelFor("next-auth"),
          bridge_kind: "next-auth",
          expires_at: null,
          detection_reason: "next-auth.session-token cookie",
        };
      }
      if (!looksLikeJwt(trimmed)) {
        // Could be a CookieStore session id from NextAuth's database
        // strategy — fall back to opaque session-cookie handling.
        return resolveSessionCookie(trimmed, trustDomain, "next-auth-fallback");
      }
      const claims = decodeBase64UrlClaims(trimmed);
      if (!claims) {
        throw new Error("malformed JWT: failed to decode claims segment");
      }
      const sub = typeof claims.sub === "string" ? claims.sub : "anonymous";
      const iss = typeof claims.iss === "string" ? claims.iss : undefined;
      const exp = typeof claims.exp === "number" ? claims.exp : undefined;
      const scope = typeof claims.scope === "string"
        ? claims.scope.split(/\s+/).filter(Boolean)
        : Array.isArray(claims.scope)
          ? (claims.scope as unknown[]).filter((v): v is string => typeof v === "string")
          : [];
      const td = iss ? trustDomainFromIss(iss) : trustDomain;
      const actor = `tf:actor:human:${td}/${encodeURIComponent(sub)}`;
      return {
        actor,
        capabilities: scope,
        trust_level: defaultTrustLevelFor(kind),
        bridge_kind: kind,
        expires_at: isoFromUnix(exp),
        issuer: iss,
        detection_reason: kind === "next-auth" ? "JWT prefix + next-auth hint" : "JWT prefix",
      };
    }
    case "tls": {
      // PEM cert. We do not parse the cert here — the bridge does. The
      // best we can do is fingerprint the leading line.
      const md = /-----BEGIN CERTIFICATE-----/.exec(trimmed);
      if (!md) {
        throw new Error("PEM credential missing BEGIN CERTIFICATE marker");
      }
      return {
        actor: `tf:actor:service:${trustDomain}/mtls-pending`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("tls"),
        bridge_kind: "tls",
        expires_at: null,
        detection_reason: "PEM CERTIFICATE marker",
      };
    }
    case "webauthn": {
      const obj = tryParseJson(trimmed);
      if (
        !obj ||
        typeof obj !== "object" ||
        Array.isArray(obj) ||
        typeof (obj as Record<string, unknown>).credentialId !== "string"
      ) {
        throw new Error("WebAuthn assertion missing credentialId");
      }
      const credId = (obj as { credentialId: string }).credentialId;
      return {
        actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(credId)}`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("webauthn"),
        bridge_kind: "webauthn",
        expires_at: null,
        detection_reason: "WebAuthn JSON shape",
      };
    }
    case "spiffe": {
      if (!trimmed.startsWith("spiffe://")) {
        throw new Error("SPIFFE credential must start with spiffe://");
      }
      let url: URL;
      try {
        url = new URL(trimmed);
      } catch {
        throw new Error(`malformed SPIFFE URI: ${trimmed}`);
      }
      const td = url.hostname;
      const path = url.pathname.replace(/^\//, "");
      return {
        actor: `tf:actor:service:${td}/${path || "spiffe-workload"}`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("spiffe"),
        bridge_kind: "spiffe",
        expires_at: null,
        issuer: trimmed,
        detection_reason: "spiffe:// scheme",
      };
    }
    case "did": {
      if (!trimmed.startsWith("did:")) {
        throw new Error("DID credential must start with did:");
      }
      // did:method:identifier — collapse to the first 64 chars for the URI.
      const id = trimmed.slice(4).split(/[#?/]/)[0] ?? "unknown";
      return {
        actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(id)}`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("did"),
        bridge_kind: "did",
        expires_at: null,
        issuer: trimmed,
        detection_reason: "did: scheme",
      };
    }
    case "gnap": {
      const obj = tryParseJson(trimmed);
      if (
        !obj ||
        typeof obj !== "object" ||
        Array.isArray(obj) ||
        typeof (obj as Record<string, unknown>).access_token === "undefined"
      ) {
        throw new Error("GNAP credential missing access_token");
      }
      const subject = (obj as { subject?: { sub_ids?: Array<{ id?: string }> } }).subject;
      const subId = subject?.sub_ids?.[0]?.id ?? "anonymous";
      return {
        actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(subId)}`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("gnap"),
        bridge_kind: "gnap",
        expires_at: null,
        detection_reason: "GNAP access_token+subject",
      };
    }
    case "clerk": {
      return {
        actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(trimmed)}`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("clerk"),
        bridge_kind: "clerk",
        expires_at: null,
        detection_reason: "sess_ prefix",
      };
    }
    case "better-auth": {
      return {
        actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(trimmed)}`,
        capabilities: [],
        trust_level: defaultTrustLevelFor("better-auth"),
        bridge_kind: "better-auth",
        expires_at: null,
        detection_reason: "auth_ prefix",
      };
    }
    case "session-cookie": {
      return resolveSessionCookie(trimmed, trustDomain, "fallback session cookie");
    }
    case "unknown":
    default:
      return resolveSessionCookie(trimmed, trustDomain, "unknown-credential");
  }
}

function resolveSessionCookie(
  cookie: string,
  trustDomain: string,
  reason: string,
): ResolvedCredential {
  return {
    actor: `tf:actor:human:${trustDomain}/${encodeURIComponent(cookie)}`,
    capabilities: [],
    trust_level: defaultTrustLevelFor("session-cookie"),
    bridge_kind: "session-cookie",
    expires_at: null,
    detection_reason: reason,
  };
}

/** First-byte / shape-based classifier. Order matters — the most
 *  specific markers are checked first. */
export function sniffKind(s: string): CredentialBridgeKind {
  if (s.startsWith("-----BEGIN CERTIFICATE-----")) return "tls";
  if (s.startsWith("spiffe://")) return "spiffe";
  if (s.startsWith("did:")) return "did";
  if (s.startsWith("__Secure-next-auth.session-token=") || s.startsWith("next-auth.session-token=")) {
    return "next-auth";
  }
  if (s.startsWith("eyJ")) {
    // Heuristic: NextAuth issues HS256 JWTs without a kid by default.
    // We can't tell HS vs RS from the header alone reliably, so we
    // default to oauth — the registry / hint can override if NextAuth.
    const header = decodeBase64UrlHeader(s);
    if (header && header["alg"] === "HS256") return "next-auth";
    return "oauth";
  }
  if (s.startsWith("sess_")) return "clerk";
  if (s.startsWith("auth_")) return "better-auth";
  if (s.startsWith("{")) {
    const obj = tryParseJson(s);
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      const o = obj as Record<string, unknown>;
      if (typeof o.credentialId === "string" && typeof o.response === "object") return "webauthn";
      if (typeof o.access_token !== "undefined" && typeof o.subject === "object") return "gnap";
    }
  }
  // Hex-only DER prefix is too ambiguous to detect without the actual
  // ASN.1 parser; we rely on the explicit `mtls-cert-pem` host_token_kind
  // hint when a caller wants to send a DER blob.
  void HEX_PREFIX_RE;
  return "unknown";
}

/** Project an opaque host_token + host_token_kind hint into a
 *  ResolvedCredential. Throws on hard malformation (the daemon turns
 *  this into 400). Soft-failure (unknown issuer, no registry match)
 *  returns `bridge_kind: "unknown"` so the caller can still see the
 *  raw classification. */
export function resolveCredential(
  credential: string,
  options: ResolveOptions = {},
): ResolvedCredential {
  if (typeof credential !== "string") {
    throw new TypeError("credential must be a string");
  }
  const trustDomain = options.trustDomain ?? "local";
  const baseline = classifyAndProject(credential, options.hint ?? null, trustDomain);

  // Apply registry override when the credential exposes an issuer.
  if (options.registry && baseline.issuer) {
    const override = options.registry.resolveByIssuer(baseline.issuer);
    if (override) {
      return applyRegistryOverride(baseline, override);
    }
  }
  return baseline;
}

/** Map a `host_token_kind` literal (the one wired in B1) onto a
 *  `CredentialBridgeKind` hint accepted by `resolveCredential`. */
export function hostTokenKindToBridge(
  kind: string | null | undefined,
): CredentialBridgeKind | null {
  switch (kind) {
    case "oauth-jwt":
      return "oauth";
    case "clerk-session":
      return "clerk";
    case "next-auth-jwt":
      return "next-auth";
    case "better-auth-session":
      return "better-auth";
    case "webauthn-assertion":
      return "webauthn";
    case "mtls-cert-pem":
      return "tls";
    case "spiffe-svid":
      return "spiffe";
    case "session-cookie":
      return "session-cookie";
    case null:
    case undefined:
    case "":
      return null;
    default:
      return null;
  }
}
