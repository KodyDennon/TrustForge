/**
 * GNAP (Grant Negotiation and Authorization Protocol — RFC 9635) bridge.
 *
 * Where the OAuth bridge accepts a JWT bearer token and projects its
 * verified claims, the GNAP bridge models the four-step grant lifecycle:
 * `start → continue → access` plus the optional `interact` redirect.
 * It also verifies DPoP-style proof-of-possession (RFC 9449) so the
 * resulting TrustForge identity is bound to a key the client controls,
 * not just a bearer secret.
 *
 * The bridge does not run an HTTP server; it provides:
 *   - typed request/response shapes for grant_request, continue, access
 *   - DPoP proof verification against an access-token thumbprint
 *   - projection of an issued GNAP grant into an ActorIdentity +
 *     Capability[]
 */

import { jwtVerify, importJWK, createLocalJWKSet, calculateJwkThumbprint } from "./jws.js";

import type { ActorIdentity } from "../generated/actor-identity.js";
import type { Capability } from "../generated/_common.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";
import { projectJwkToPublicKey } from "./bridge-oauth.js";

export type GnapAccessRight = string | { actions?: string[]; locations?: string[]; type?: string };

export interface GnapClient {
  /** Stable identifier for the client (e.g. URL or random nonce). */
  id?: string;
  /** Public key the client uses for proof-of-possession. */
  key: GnapKeyDescriptor;
  /** Optional display name shown on interaction screens. */
  display?: { name?: string; uri?: string };
}

export interface GnapKeyDescriptor {
  /** RFC 9421 / RFC 9449 proof method. */
  proof: "httpsig" | "dpop" | "jwsd";
  /** JWK form of the client's public key. */
  jwk: Record<string, unknown>;
}

export interface GnapAccessTokenRequest {
  access: GnapAccessRight[];
  /** Optional friendly label so audit logs can name the grant. */
  label?: string;
  flags?: ("bearer" | "durable")[];
}

export interface GnapGrantRequest {
  client: GnapClient;
  access_token: GnapAccessTokenRequest | GnapAccessTokenRequest[];
  /** Subject information requested from the AS (RFC 9635 §2.4). */
  subject?: { sub_id_formats?: string[]; assertion_formats?: string[] };
  /** Interact section (currently we only support `redirect` flow). */
  interact?: { start: string[]; finish?: { method: "redirect"; uri: string; nonce: string } };
}

export interface GnapAccessTokenResponse {
  value: string;
  bound: boolean;
  manage?: { uri: string; access_token?: { value: string } };
  expires_in?: number;
}

export interface GnapGrantResponse {
  access_token: GnapAccessTokenResponse;
  subject?: { sub_ids?: Array<{ format: string; id: string }> };
  /** When set the request still needs interaction; `continue` carries the
   *  URI the client polls. */
  interact?: { redirect: string; finish?: string };
  continue?: { uri: string; access_token: { value: string }; wait?: number };
}

export interface GnapBridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Issuer identifier to embed in the projected ActorIdentity. */
  issuer: string;
  /** Allow-list of access-token signing algorithms. */
  allowedAlgorithms: ("ES256" | "ES384" | "EdDSA" | "RS256")[];
  /** JWKS that signed the access token (the AS's signing key set). */
  jwks: { keys: Record<string, unknown>[] };
  /** Optional override mapping access right `actions` to TrustForge action names. */
  actionMapper?: (right: GnapAccessRight) => string[];
  /** Default risk for capabilities derived from the grant. */
  defaultCapabilityRisk?: Capability["risk"];
}

export interface GnapVerifiedGrant {
  identity: ActorIdentity;
  capabilities: Capability[];
  /** Hex-encoded JWK thumbprint (RFC 7638) of the client key the AS
   *  bound the token to. Use this for DPoP enforcement. */
  clientKeyThumbprint: string;
}

export interface DpopProofVerification {
  ok: boolean;
  reason?: string;
  jktExpected?: string;
  jktSeen?: string;
}

const HTTPSIG_FLOWS = new Set(["redirect"]);

export class GnapBridge implements Bridge {
  readonly kind: BridgeKind = "gnap";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: GnapBridgeConfig;

  constructor(cfg: GnapBridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
  }

  /** Validate a `start` request and produce a deterministic
   *  GnapGrantResponse representing what an AS would emit. The AS itself
   *  is out of scope for the bridge — this method just produces a shape
   *  the caller can use as a stub or in tests. */
  buildGrantResponse(req: GnapGrantRequest, opts: { token: string; finishUri?: string; interactUri?: string }): GnapGrantResponse {
    if (!req.client?.key?.jwk || !req.client.key.proof) {
      throw new BridgeFailure({ code: "invalid-input", message: "client.key.jwk + proof required" });
    }
    if (Array.isArray(req.access_token)
      ? req.access_token.length === 0
      : !req.access_token.access || req.access_token.access.length === 0) {
      throw new BridgeFailure({ code: "invalid-input", message: "access_token.access required" });
    }
    if (req.interact && !req.interact.start.every((s) => HTTPSIG_FLOWS.has(s))) {
      throw new BridgeFailure({ code: "unsupported", message: "only `redirect` interact flow supported" });
    }
    const out: GnapGrantResponse = {
      access_token: {
        value: opts.token,
        bound: true,
        expires_in: 600,
      },
    };
    if (req.interact?.finish && opts.interactUri) {
      out.interact = { redirect: opts.interactUri, finish: req.interact.finish.nonce };
    }
    if (opts.finishUri) {
      out.continue = {
        uri: opts.finishUri,
        access_token: { value: `cont-${opts.token.slice(-8)}` },
      };
    }
    return out;
  }

  /** Verify a JWT-shaped GNAP access token and project the verified
   *  claims + the client key binding into a TrustForge identity. */
  async verifyAccessToken(
    token: string,
    request: GnapGrantRequest,
  ): Promise<GnapVerifiedGrant> {
    if (!token) {
      throw new BridgeFailure({ code: "invalid-input", message: "missing access token" });
    }
    if (!request.client?.key?.jwk) {
      throw new BridgeFailure({ code: "invalid-input", message: "client.key.jwk required" });
    }
    const jwks = createLocalJWKSet({ keys: this.cfg.jwks.keys as { kty: string }[] } as never);
    let payload: Record<string, unknown>;
    try {
      const { payload: p } = await jwtVerify(token, jwks, {
        issuer: this.cfg.issuer,
        algorithms: this.cfg.allowedAlgorithms,
      });
      payload = p as Record<string, unknown>;
    } catch (e) {
      throw new BridgeFailure({ code: "rejected", message: `GNAP access token verify failed: ${(e as Error).message}` });
    }
    const cnf = (payload["cnf"] as Record<string, unknown> | undefined) ?? null;
    const expectedJkt = await calculateJwkThumbprint(request.client.key.jwk as never, "sha256");
    if (cnf && typeof cnf["jkt"] === "string" && cnf["jkt"] !== expectedJkt) {
      throw new BridgeFailure({ code: "rejected", message: "access token cnf.jkt does not match client.key" });
    }
    const subject = String(payload["sub"] ?? "anonymous");
    const actorType = (payload["tf_actor_type"] as string | undefined) ?? "agent";
    const actorId = `tf:actor:${actorType}:${this.cfg.trustDomain}/${encodeURIComponent(subject)}`;
    const accessRights = flattenAccess(request.access_token);
    const mapper = this.cfg.actionMapper ?? defaultActionMapper;
    const actions = accessRights.flatMap((r) => mapper(r));
    const capabilities: Capability[] = actions.map((name) => ({
      name,
      risk: this.cfg.defaultCapabilityRisk ?? "R2",
    }));
    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: actorId,
      actor_type: actorType as ActorIdentity["actor_type"],
      public_keys: [projectJwkToPublicKey(request.client.key.jwk)],
      trust_levels: ["T3"],
      authority_roots: [
        { kind: "organization", id: this.cfg.issuer },
      ],
      valid_from: payload["iat"] ? new Date(Number(payload["iat"]) * 1000).toISOString() : new Date().toISOString(),
      valid_until: payload["exp"] ? new Date(Number(payload["exp"]) * 1000).toISOString() : undefined,
    };
    return { identity, capabilities, clientKeyThumbprint: expectedJkt };
  }

  /** Verify an RFC 9449 DPoP proof JWT against the bound access token.
   *  Caller passes the proof header value, the HTTP method, the
   *  destination URL, and (optionally) the access token's hash so we
   *  can compare `ath`. */
  async verifyDpopProof(
    proofJwt: string,
    opts: {
      htm: string;
      htu: string;
      accessTokenHash?: string;
      expectedJkt: string;
    },
  ): Promise<DpopProofVerification> {
    if (!proofJwt) {
      return { ok: false, reason: "missing DPoP proof" };
    }
    const parts = proofJwt.split(".");
    if (parts.length !== 3) {
      return { ok: false, reason: "DPoP proof not a JWT" };
    }
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(parts[0]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
    } catch (e) {
      return { ok: false, reason: `DPoP header parse failed: ${(e as Error).message}` };
    }
    if (header["typ"] !== "dpop+jwt") {
      return { ok: false, reason: `DPoP typ ${header["typ"]} is not dpop+jwt` };
    }
    const jwk = header["jwk"] as Record<string, unknown> | undefined;
    if (!jwk) return { ok: false, reason: "DPoP header missing jwk" };
    const jkt = await calculateJwkThumbprint(jwk as never, "sha256");
    if (jkt !== opts.expectedJkt) {
      return { ok: false, reason: "jkt mismatch", jktExpected: opts.expectedJkt, jktSeen: jkt };
    }
    let key;
    try {
      key = await importJWK(jwk as never, header["alg"] as string);
    } catch (e) {
      return { ok: false, reason: `failed to import DPoP jwk: ${(e as Error).message}` };
    }
    let payload: Record<string, unknown>;
    try {
      const { payload: p } = await jwtVerify(proofJwt, key as never, {
        algorithms: this.cfg.allowedAlgorithms,
        typ: "dpop+jwt",
      });
      payload = p as Record<string, unknown>;
    } catch (e) {
      return { ok: false, reason: `DPoP signature verify failed: ${(e as Error).message}` };
    }
    if (payload["htm"] !== opts.htm) {
      return { ok: false, reason: `DPoP htm ${payload["htm"]} does not match expected ${opts.htm}` };
    }
    if (payload["htu"] !== opts.htu) {
      return { ok: false, reason: `DPoP htu ${payload["htu"]} does not match expected ${opts.htu}` };
    }
    if (opts.accessTokenHash && payload["ath"] !== opts.accessTokenHash) {
      return { ok: false, reason: `DPoP ath does not match expected access-token hash` };
    }
    if (typeof payload["iat"] !== "number") {
      return { ok: false, reason: "DPoP missing iat" };
    }
    return { ok: true, jktExpected: opts.expectedJkt, jktSeen: jkt };
  }
}

function flattenAccess(req: GnapAccessTokenRequest | GnapAccessTokenRequest[]): GnapAccessRight[] {
  if (Array.isArray(req)) return req.flatMap((r) => r.access);
  return req.access;
}

function defaultActionMapper(right: GnapAccessRight): string[] {
  if (typeof right === "string") return [right];
  return right.actions ?? [];
}
