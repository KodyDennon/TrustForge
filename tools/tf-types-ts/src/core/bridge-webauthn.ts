/**
 * WebAuthn bridge. Takes a structured credential (public key + RP ID +
 * user handle) and builds a TrustForge actor-identity document that
 * downstream code can store in the vault / sign with.
 *
 * Parsing of the browser's raw attestationObject (CBOR) is out of scope
 * here — the caller is expected to have extracted the fields already.
 * See TF-0009 for the roadmap of full attestation-chain verification.
 */

import type { ActorIdentity } from "../generated/actor-identity.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";

export type WebAuthnAlgorithm = "ed25519" | "p256" | "rsa-pss-sha256";

export interface WebAuthnCredential {
  credential_id: string; // base64url
  public_key: string; // base64, raw (not COSE-wrapped) public key bytes
  algorithm: WebAuthnAlgorithm;
  rp_id: string;
  user_handle: string; // base64url; opaque user ID from the RP
  aaguid?: string;
  attestation_format?: "none" | "packed" | "fido-u2f" | "tpm";
  valid_from?: string;
  valid_until?: string;
}

export interface WebAuthnBridgeConfig {
  bridgeId: string;
  rpId: string;
  allowedAlgorithms?: WebAuthnAlgorithm[];
}

function slug(base64url: string): string {
  // Convert base64url to a url-safe string for embedding in an actor URI.
  return base64url.replace(/=+$/, "").replace(/\//g, "_").replace(/\+/g, "-");
}

export function webauthnToActorIdentity(
  cred: WebAuthnCredential,
  opts: { rpId?: string; allowedAlgorithms?: WebAuthnAlgorithm[] } = {},
): ActorIdentity {
  if (!cred.public_key) throw new BridgeFailure({ code: "invalid-input", message: "missing public_key" });
  if (!cred.rp_id) throw new BridgeFailure({ code: "invalid-input", message: "missing rp_id" });
  if (!cred.user_handle) throw new BridgeFailure({ code: "invalid-input", message: "missing user_handle" });
  if (opts.rpId && opts.rpId !== cred.rp_id) {
    throw new BridgeFailure({
      code: "rejected",
      message: `credential rp_id ${cred.rp_id} does not match bridge rp_id ${opts.rpId}`,
    });
  }
  const allowed = opts.allowedAlgorithms ?? ["ed25519", "p256", "rsa-pss-sha256"];
  if (!allowed.includes(cred.algorithm)) {
    throw new BridgeFailure({
      code: "rejected",
      message: `algorithm ${cred.algorithm} is not in the bridge's allow-list`,
    });
  }

  const now = new Date().toISOString();
  const identity: ActorIdentity = {
    identity_version: "1",
    actor_id: `tf:actor:human:${cred.rp_id}/${slug(cred.user_handle)}`,
    actor_type: "human",
    public_keys: [
      {
        key_id: cred.credential_id,
        algorithm: cred.algorithm,
        public_key: cred.public_key,
        purpose: "signing",
        valid_from: cred.valid_from,
        valid_until: cred.valid_until,
      },
    ],
    trust_levels: ["T4"],
    authority_roots: [
      {
        kind: "hardware-key",
        id: cred.aaguid ?? "(unknown-aaguid)",
      },
    ],
    valid_from: cred.valid_from ?? now,
    valid_until: cred.valid_until,
  };
  return identity;
}

export function actorIdentityToWebauthn(identity: ActorIdentity): WebAuthnCredential {
  if (identity.actor_type !== "human") {
    throw new BridgeFailure({
      code: "unsupported",
      message: `WebAuthn bridge only reverses human actors, got ${identity.actor_type}`,
    });
  }
  const hardwareRoot = identity.authority_roots.find((r) => r.kind === "hardware-key");
  if (!hardwareRoot) {
    throw new BridgeFailure({
      code: "rejected",
      message: "identity's authority_roots does not include hardware-key",
    });
  }
  const key = identity.public_keys[0];
  if (!key) {
    throw new BridgeFailure({ code: "invalid-input", message: "identity has no public_keys" });
  }
  const match = /^tf:actor:human:([^/]+)\/(.+)$/.exec(identity.actor_id);
  if (!match) {
    throw new BridgeFailure({ code: "invalid-input", message: `malformed actor URI: ${identity.actor_id}` });
  }
  const [, rpId, userHandle] = match;
  return {
    credential_id: key.key_id,
    public_key: key.public_key,
    algorithm: key.algorithm as WebAuthnAlgorithm,
    rp_id: rpId!,
    user_handle: userHandle!,
    aaguid: hardwareRoot.id === "(unknown-aaguid)" ? undefined : hardwareRoot.id,
    valid_from: identity.valid_from,
    valid_until: identity.valid_until,
  };
}

export class WebAuthnBridge implements Bridge {
  readonly kind: BridgeKind = "webauthn";
  constructor(
    public readonly bridgeId: string,
    public readonly trustDomain: string,
    private readonly cfg: WebAuthnBridgeConfig,
  ) {}

  accept(cred: WebAuthnCredential): ActorIdentity {
    return webauthnToActorIdentity(cred, {
      rpId: this.cfg.rpId,
      allowedAlgorithms: this.cfg.allowedAlgorithms,
    });
  }

  project(identity: ActorIdentity): WebAuthnCredential {
    return actorIdentityToWebauthn(identity);
  }
}
