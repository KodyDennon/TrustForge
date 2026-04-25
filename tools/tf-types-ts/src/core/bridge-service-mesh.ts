/**
 * Service-mesh bridge — accepts the headers an Envoy / Istio / Linkerd
 * sidecar puts on inbound mTLS connections (X-Forwarded-Client-Cert
 * for Envoy, the SPIFFE SVID propagated as a JWT for Istio) and
 * projects the verified peer identity into a TrustForge ActorIdentity.
 *
 * The bridge composes the existing TLS + SPIFFE bridges:
 *   - Envoy XFCC → certificate chain → TLS bridge
 *   - Istio Authorization JWT → SPIFFE SVID → SPIFFE bridge
 *
 * It does not parse Envoy's full XFCC syntax — it accepts the typed
 * fields (URI, By, Hash, Subject) the upstream proxy passes through.
 */

import type { ActorIdentity } from "../generated/actor-identity.js";
import type { Capability } from "../generated/_common.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";
import { spiffeToActorId } from "./bridge-spiffe.js";
import { TlsBridge, type TlsBridgeConfig } from "./bridge-tls.js";
import { sha256 } from "@noble/hashes/sha2";

/** Build a `sha256:<hex>` fingerprint of a UTF-8 string. Used by mesh
 *  bridges to fill the public_key slot of an `external-attestation`
 *  pseudo-key with a non-cryptographic-but-deterministic value. */
function toHexFingerprint(s: string): string {
  const digest = sha256(new TextEncoder().encode(s));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

export type ServiceMeshKind = "envoy-xfcc" | "istio-authn" | "linkerd-l5d";

export interface XfccEntry {
  /** SPIFFE ID URI from the SAN (XFCC `URI=`). */
  uri?: string;
  /** Certificate hash (XFCC `Hash=`). */
  hash?: string;
  /** Issuer subject (XFCC `By=`). */
  by?: string;
  /** Leaf subject (XFCC `Subject=`). */
  subject?: string;
}

export interface IstioAuthnContext {
  /** SPIFFE ID embedded in the JWT (e.g. `spiffe://example.com/ns/foo/sa/bar`). */
  spiffe_id: string;
  /** Optional namespace + service-account fields parsed by the bridge. */
  namespace?: string;
  service_account?: string;
}

export interface LinkerdContext {
  /** Linkerd `l5d-client-id` header value. */
  client_id: string;
}

export interface ServiceMeshBridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Default capability risk for projected identities. */
  defaultRisk?: Capability["risk"];
  /** When the mesh hands us a certificate chain (Envoy mTLS termination)
   *  we forward it to a TlsBridge. Omit when only XFCC URI is needed. */
  tls?: TlsBridgeConfig;
}

export interface ServiceMeshAcceptResult {
  identity: ActorIdentity;
  capabilities: Capability[];
  source: ServiceMeshKind;
}

export class ServiceMeshBridge implements Bridge {
  readonly kind: BridgeKind = "service-mesh";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: ServiceMeshBridgeConfig;
  private readonly tlsBridge?: TlsBridge;

  constructor(cfg: ServiceMeshBridgeConfig) {
    this.cfg = cfg;
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    if (cfg.tls) this.tlsBridge = new TlsBridge(cfg.tls);
  }

  /** Project an Envoy `X-Forwarded-Client-Cert` entry. The proxy
   *  already verified the chain — the bridge only re-derives the
   *  identity. When `cfg.tls` is set and the entry contains a chain,
   *  the chain is also re-validated through the TLS bridge. */
  acceptEnvoy(entry: XfccEntry, chainPem?: string[]): ServiceMeshAcceptResult {
    if (!entry.uri && !entry.subject) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: "XFCC entry must include at least URI or Subject",
      });
    }
    if (chainPem && chainPem.length > 0 && this.tlsBridge) {
      const result = this.tlsBridge.verifyChain(chainPem);
      return {
        identity: result.identity,
        capabilities: result.capabilities,
        source: "envoy-xfcc",
      };
    }
    if (entry.uri && entry.uri.startsWith("spiffe://")) {
      const actor = spiffeToActorId(entry.uri);
      // The mesh authenticates this peer at the L4/L5 layer; the
      // daemon doesn't hold a key for it. We emit an explicit
      // "external-attestation" entry whose `public_key` value is the
      // mesh's own attestation hash (the XFCC `hash` if present, else
      // the canonical SVID URI). Pre-B9 we fabricated a 1-byte zero
      // ed25519 key — a deceptive identity that schema-validated.
      const attestationDigest = entry.hash ?? toHexFingerprint(entry.uri);
      const identity: ActorIdentity = {
        identity_version: "1",
        actor_id: actor,
        actor_type: "service",
        public_keys: [
          {
            key_id: entry.hash ?? "envoy-xfcc",
            algorithm: "external-attestation",
            public_key: attestationDigest,
            purpose: "attestation",
          },
        ],
        trust_levels: ["T3"],
        authority_roots: [
          {
            kind: "federation",
            id: entry.by ?? "envoy",
          },
        ],
        valid_from: new Date().toISOString(),
      };
      return {
        identity,
        capabilities: [{ name: "service.connect", risk: this.cfg.defaultRisk ?? "R2" }],
        source: "envoy-xfcc",
      };
    }
    throw new BridgeFailure({
      code: "rejected",
      message: "XFCC entry without SPIFFE URI requires a chainPem to verify",
    });
  }

  /** Project an Istio authentication context (SPIFFE id from a JWT). */
  acceptIstio(ctx: IstioAuthnContext): ServiceMeshAcceptResult {
    if (!ctx.spiffe_id?.startsWith("spiffe://")) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: "Istio context.spiffe_id must be a spiffe:// URI",
      });
    }
    const actor = spiffeToActorId(ctx.spiffe_id);
    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: actor,
      actor_type: "service",
      public_keys: [
        {
          key_id: "istio-authn",
          algorithm: "external-attestation",
          public_key: toHexFingerprint(ctx.spiffe_id),
          purpose: "attestation",
        },
      ],
      trust_levels: ["T3"],
      authority_roots: [
        {
          kind: "federation",
          id: "istio",
        },
      ],
      valid_from: new Date().toISOString(),
    };
    return {
      identity,
      capabilities: [{ name: "service.connect", risk: this.cfg.defaultRisk ?? "R2" }],
      source: "istio-authn",
    };
  }

  /** Project a Linkerd `l5d-client-id` header. Linkerd uses
   *  `<sa>.<ns>.serviceaccount.identity.linkerd.cluster.local` style
   *  identifiers; we map them to `tf:actor:service:<cluster>/<ns>/<sa>`. */
  acceptLinkerd(ctx: LinkerdContext): ServiceMeshAcceptResult {
    const m = /^([^.]+)\.([^.]+)\.serviceaccount\.identity\.([^.]+)\.cluster\.local$/.exec(
      ctx.client_id,
    );
    if (!m) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: `Linkerd client_id ${ctx.client_id} does not match expected shape`,
      });
    }
    const [, sa, ns, cluster] = m;
    const actor = `tf:actor:service:${cluster!}/${ns!}/${sa!}`;
    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: actor,
      actor_type: "service",
      public_keys: [
        {
          key_id: "linkerd-l5d",
          algorithm: "external-attestation",
          public_key: toHexFingerprint(ctx.client_id),
          purpose: "attestation",
        },
      ],
      trust_levels: ["T3"],
      authority_roots: [{ kind: "federation", id: "linkerd" }],
      valid_from: new Date().toISOString(),
    };
    return {
      identity,
      capabilities: [{ name: "service.connect", risk: this.cfg.defaultRisk ?? "R2" }],
      source: "linkerd-l5d",
    };
  }
}
