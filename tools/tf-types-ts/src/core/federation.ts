/**
 * Federation primitives — sign / verify cross-trust-domain attestations,
 * plus an in-memory FederatedTrustStore that bridges (SPIFFE, TLS, DID,
 * service-mesh) consult to recognise peer identities from other
 * domains.
 *
 * Federation flow:
 *   1. Domain A's authority signs a `FederationAttestation` declaring
 *      "I recognise domain B (or actor X in B) within scope S, for
 *      duration T, backed by trust_bundle TB".
 *   2. Domain A loads the attestation into its local
 *      `FederatedTrustStore` so its bridges can answer
 *      `isFederated(actor, domain)`.
 *   3. When a cross-domain peer presents an identity (SPIFFE SVID,
 *      DID, TLS cert), the relevant bridge calls
 *      `FederatedTrustStore.verifyForeign(...)` to confirm the peer's
 *      domain is recognised AND the peer's signature verifies against
 *      one of the bundle keys.
 */

import type {
  ActionName,
  ActorId,
  Capability,
  Constraint,
  SignatureEnvelope,
  Timestamp,
  TrustDomain,
  TrustLevel,
} from "../generated/_common.js";
import type { FederationAttestation } from "../generated/federation-attestation.js";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify, sha256 } from "./crypto.js";
import { isWithinWindow } from "./expiration.js";

export type TrustBundleEntry = FederationAttestation["trust_bundle"][number];

export interface SignFederationAttestationArgs {
  attestationId: string;
  issuerDomain: TrustDomain;
  subjectDomain: TrustDomain;
  subjectActor?: ActorId;
  scope?: ActionName[];
  trustLevelsGranted?: TrustLevel[];
  trustBundle: TrustBundleEntry[];
  constraints?: Constraint[];
  issuedAt?: Timestamp;
  validUntil: Timestamp;
  issuer: ActorId;
  privateKey: Uint8Array;
}

export function attestationSigningBytes(a: FederationAttestation): Uint8Array {
  const { signature: _signature, ...rest } = a;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

export async function signFederationAttestation(
  args: SignFederationAttestationArgs,
): Promise<FederationAttestation> {
  if (args.trustBundle.length === 0) {
    throw new Error("federation attestation requires a non-empty trust_bundle");
  }
  const draft: FederationAttestation = {
    attestation_version: "1",
    attestation_id: args.attestationId,
    issuer_domain: args.issuerDomain,
    subject_domain: args.subjectDomain,
    trust_bundle: args.trustBundle,
    issued_at: args.issuedAt ?? new Date().toISOString(),
    valid_until: args.validUntil,
    issuer: args.issuer,
    signature: { algorithm: "ed25519", signer: args.issuer, signature: "" } as SignatureEnvelope,
  };
  if (args.subjectActor) draft.subject_actor = args.subjectActor;
  if (args.scope && args.scope.length > 0) draft.scope = args.scope;
  if (args.trustLevelsGranted && args.trustLevelsGranted.length > 0) {
    draft.trust_levels_granted = args.trustLevelsGranted;
  }
  if (args.constraints && args.constraints.length > 0) draft.constraints = args.constraints;
  const digest = attestationSigningBytes(draft);
  const sig = await ed25519Sign(digest, args.privateKey);
  draft.signature = {
    algorithm: "ed25519",
    signer: args.issuer,
    signature: Buffer.from(sig).toString("base64"),
  };
  return draft;
}

export interface VerifyFederationAttestationArgs {
  attestation: FederationAttestation;
  /** Public key of `attestation.issuer` (e.g. the issuer-domain root key). */
  issuerPublicKey: Uint8Array;
  now?: Timestamp;
}

export interface VerifyFederationResult {
  ok: boolean;
  reason?: string;
}

export async function verifyFederationAttestation(
  args: VerifyFederationAttestationArgs,
): Promise<VerifyFederationResult> {
  const a = args.attestation;
  if (a.attestation_version !== "1") {
    return { ok: false, reason: `unsupported version ${a.attestation_version}` };
  }
  if (a.signature.signer !== a.issuer) {
    return { ok: false, reason: "signature signer does not match issuer" };
  }
  if (a.signature.algorithm !== "ed25519") {
    return { ok: false, reason: `unsupported algorithm ${a.signature.algorithm}` };
  }
  const now = args.now ?? new Date().toISOString();
  if (!isWithinWindow({ valid_from: a.issued_at, valid_until: a.valid_until }, now)) {
    return { ok: false, reason: "attestation outside valid window" };
  }
  const digest = attestationSigningBytes(a);
  const sigBytes = new Uint8Array(Buffer.from(a.signature.signature, "base64"));
  const ok = await ed25519Verify(args.issuerPublicKey, digest, sigBytes);
  return ok ? { ok: true } : { ok: false, reason: "signature did not verify" };
}

/* -------------------------------------------------------------------------- */
/*  In-memory federated trust store                                           */
/* -------------------------------------------------------------------------- */

export interface ForeignIdentityCheck {
  ok: boolean;
  reason?: string;
  matchedAttestationId?: string;
  trustLevels?: TrustLevel[];
  scope?: ActionName[];
  capabilities?: Capability[];
}

export class FederatedTrustStore {
  private readonly attestations: Map<string, FederationAttestation> = new Map();

  /** Insert an already-verified attestation. */
  add(attestation: FederationAttestation): void {
    this.attestations.set(attestation.attestation_id, attestation);
  }

  /** Remove an attestation (e.g. on revocation). */
  remove(attestationId: string): boolean {
    return this.attestations.delete(attestationId);
  }

  list(): FederationAttestation[] {
    return [...this.attestations.values()];
  }

  /** Returns the first attestation whose subject_domain matches and
   *  whose subject_actor is either unset (whole-domain attestation) or
   *  equal to `actor`. */
  findFor(actor: ActorId, subjectDomain: TrustDomain, now?: Timestamp): FederationAttestation | undefined {
    const at = now ?? new Date().toISOString();
    for (const a of this.attestations.values()) {
      if (a.subject_domain !== subjectDomain) continue;
      if (a.subject_actor && a.subject_actor !== actor) continue;
      if (!isWithinWindow({ valid_from: a.issued_at, valid_until: a.valid_until }, at)) continue;
      return a;
    }
    return undefined;
  }

  /** Verify a foreign identity:
   *   - find an active attestation for (actor, subject_domain)
   *   - verify the foreign signature against any bundle entry that matches
   *   - return granted scope + trust levels for the caller to apply. */
  async verifyForeign(args: {
    actor: ActorId;
    subjectDomain: TrustDomain;
    /** Bytes the foreign actor signed (e.g. canonical SVID, canonical
     *  DID document, etc.). Pass an empty Uint8Array to skip signature
     *  verification — the bridge will only use the attestation
     *  metadata to answer "is this domain federated". */
    signed?: { message: Uint8Array; signature: Uint8Array };
    now?: Timestamp;
  }): Promise<ForeignIdentityCheck> {
    const at = args.actor;
    const a = this.findFor(at, args.subjectDomain, args.now);
    if (!a) {
      return { ok: false, reason: `no active attestation for ${at} in ${args.subjectDomain}` };
    }
    if (args.signed) {
      let matched = false;
      for (const entry of a.trust_bundle) {
        if (entry.kind === "ed25519") {
          const pub = new Uint8Array(Buffer.from(entry.value, "base64"));
          if (pub.length !== 32) continue;
          if (await ed25519Verify(pub, args.signed.message, args.signed.signature)) {
            matched = true;
            break;
          }
        }
      }
      if (!matched) {
        return {
          ok: false,
          reason: "no bundle key matched the foreign actor's signature",
          matchedAttestationId: a.attestation_id,
        };
      }
    }
    const capabilities = (a.scope ?? []).map((name) => ({ name, risk: "R2" } as Capability));
    return {
      ok: true,
      matchedAttestationId: a.attestation_id,
      trustLevels: a.trust_levels_granted,
      scope: a.scope,
      capabilities,
    };
  }
}

/* -------------------------------------------------------------------------- */
/*  SPIFFE federated trust bundle adapter                                     */
/* -------------------------------------------------------------------------- */

export interface SpiffeFederatedBundle {
  /** Trust domain this bundle covers (e.g. `partner.example.org`). */
  trust_domain: TrustDomain;
  /** Per RFC 8392 / SPIFFE Federation, an array of JWKs the
   *  trust-domain authority publishes. */
  keys: Array<Record<string, unknown>>;
}

/** Build a FederationAttestation from a SPIFFE federated trust bundle.
 *  Useful when the issuer wants to wrap an existing SPIFFE bundle into
 *  a TrustForge attestation so SPIFFE federation can be consumed by
 *  every other bridge. */
export function attestationFromSpiffeBundle(
  bundle: SpiffeFederatedBundle,
  args: {
    issuerDomain: TrustDomain;
    issuer: ActorId;
    validUntil: Timestamp;
  },
): Omit<FederationAttestation, "signature" | "issued_at" | "attestation_id"> {
  const trust_bundle = bundle.keys
    .filter((k) => k.kty === "OKP" && k.crv === "Ed25519" && typeof k.x === "string")
    .map((k, i) => ({
      kind: "ed25519" as const,
      key_id: typeof k.kid === "string" ? k.kid : `spiffe-${i}`,
      value: Buffer.from(base64UrlToBytes(k.x as string)).toString("base64"),
    }));
  return {
    attestation_version: "1",
    issuer_domain: args.issuerDomain,
    subject_domain: bundle.trust_domain,
    trust_bundle,
    valid_until: args.validUntil,
    issuer: args.issuer,
  } as Omit<FederationAttestation, "signature" | "issued_at" | "attestation_id">;
}

function base64UrlToBytes(b64u: string): Uint8Array {
  let s = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  return new Uint8Array(Buffer.from(s, "base64"));
}
