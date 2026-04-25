/**
 * Profile selection runtime.
 *
 * `loadProfileSpec` reads a profile-spec.schema.json document and
 * returns a typed `ProfileSpec`. `selectProfile(spec, gate)` enforces
 * the profile against a `FeatureGate` describing what the daemon
 * actually supports — every MUST entry must be present, every MUST_NOT
 * entry must be absent, EnforcementLevel must meet the floor.
 *
 * The bundled profiles (`tf-home-compatible`, `tf-enterprise-compatible`,
 * `tf-constrained-compatible`, `tf-compliance-evidence-compatible`)
 * are exposed as `BUILTIN_PROFILES` for daemons that don't ship their
 * own.
 */

import type { ProfileSpec } from "../generated/profile-spec.js";
import type { EnforcementLevel, ProofLevel } from "../generated/_common.js";

export type FeatureSet = ReadonlySet<string>;

export interface ProfileFeatureGate {
  features: FeatureSet;
  enforcementLevel: EnforcementLevel;
  proofLevelFloor: ProofLevel;
  bridges: ReadonlySet<string>;
  anchors: ReadonlySet<string>;
}

export interface ProfileVerdict {
  ok: boolean;
  profile: string;
  failures: string[];
  warnings: string[];
}

const ENF_RANK: Record<EnforcementLevel, number> = {
  E0: 0,
  E1: 1,
  E2: 2,
  E3: 3,
  E4: 4,
  E5: 5,
};

const PROOF_RANK: Record<ProofLevel, number> = {
  L0: 0,
  L1: 1,
  L2: 2,
  L3: 3,
  L4: 4,
  L5: 5,
};

export function selectProfile(
  spec: ProfileSpec,
  gate: ProfileFeatureGate,
): ProfileVerdict {
  const failures: string[] = [];
  const warnings: string[] = [];
  for (const m of spec.must) {
    if (!gate.features.has(m.id)) {
      failures.push(`profile ${spec.profile_id} requires feature "${m.id}" — missing`);
    }
  }
  if (spec.must_not) {
    for (const n of spec.must_not) {
      if (gate.features.has(n.id)) {
        failures.push(`profile ${spec.profile_id} forbids feature "${n.id}"`);
      }
    }
  }
  if (spec.should) {
    for (const s of spec.should) {
      if (!gate.features.has(s.id)) {
        warnings.push(`profile ${spec.profile_id} recommends feature "${s.id}"`);
      }
    }
  }
  if (spec.min_enforcement_level) {
    const need = ENF_RANK[spec.min_enforcement_level];
    const have = ENF_RANK[gate.enforcementLevel];
    if (have < need) {
      failures.push(
        `profile ${spec.profile_id} requires EnforcementLevel ≥ ${spec.min_enforcement_level}, daemon at ${gate.enforcementLevel}`,
      );
    }
  }
  if (spec.min_proof_level) {
    const need = PROOF_RANK[spec.min_proof_level];
    const have = PROOF_RANK[gate.proofLevelFloor];
    if (have < need) {
      failures.push(
        `profile ${spec.profile_id} requires proof level floor ≥ ${spec.min_proof_level}, daemon at ${gate.proofLevelFloor}`,
      );
    }
  }
  if (spec.required_bridges) {
    for (const b of spec.required_bridges) {
      if (!gate.bridges.has(b)) {
        failures.push(`profile ${spec.profile_id} requires bridge ${b} — missing`);
      }
    }
  }
  if (spec.required_anchors) {
    for (const a of spec.required_anchors) {
      if (!gate.anchors.has(a)) {
        failures.push(`profile ${spec.profile_id} requires anchor ${a} — missing`);
      }
    }
  }
  return {
    ok: failures.length === 0,
    profile: spec.profile_id,
    failures,
    warnings,
  };
}

/** Built-in profile specs. The same content as the fixtures under
 *  `schemas/fixtures/profile-spec/valid/`. Daemons can reach for
 *  these without bundling extra files. */
export const BUILTIN_PROFILES: Record<string, ProfileSpec> = {
  "tf-home-compatible": {
    profile_version: "1",
    profile_id: "tf-home-compatible",
    label: "TrustForge home / personal-network profile",
    must: [
      { id: "agent-contract" },
      { id: "proof-log" },
      { id: "ed25519" },
      { id: "vault" },
    ],
    should: [{ id: "webauthn" }, { id: "shadow-mode" }],
    min_enforcement_level: "E3",
    min_proof_level: "L1",
  },
  "tf-enterprise-compatible": {
    profile_version: "1",
    profile_id: "tf-enterprise-compatible",
    label: "TrustForge enterprise profile",
    must: [
      { id: "policy-engine" },
      { id: "quorum-collector" },
      { id: "continuous-reauth" },
      { id: "transparency-anchor.any" },
      { id: "federation" },
      { id: "webauthn" },
      { id: "agent-contract" },
    ],
    should: [{ id: "shadow-mode" }, { id: "hybrid-pq" }],
    required_bridges: ["webauthn", "oauth", "spiffe"],
    required_anchors: ["rfc6962"],
    min_enforcement_level: "E4",
    min_proof_level: "L2",
  },
  "tf-constrained-compatible": {
    profile_version: "1",
    profile_id: "tf-constrained-compatible",
    label: "TrustForge constrained / LoRa / offline profile",
    must: [
      { id: "packet-mode" },
      { id: "fragment-reassembly" },
      { id: "offline-revocation-list" },
      { id: "emergency-authority" },
    ],
    must_not: [{ id: "transport.websocket-only" }, { id: "transparency-anchor.always-online" }],
    should: [{ id: "cbor-encoding" }, { id: "deflate-compression" }],
    min_enforcement_level: "E3",
    min_proof_level: "L1",
  },
  "tf-compliance-evidence-compatible": {
    profile_version: "1",
    profile_id: "tf-compliance-evidence-compatible",
    label: "TrustForge compliance / legal-evidence profile",
    must: [
      { id: "policy-engine" },
      { id: "quorum-collector" },
      { id: "signed-log-events" },
      { id: "evidence-bundle" },
      { id: "l4-encrypted-bundle" },
      { id: "l5-rfc3161-anchor" },
      { id: "continuous-reauth" },
    ],
    should: [{ id: "redaction" }, { id: "federation" }],
    required_anchors: ["rfc6962", "rfc3161"],
    min_enforcement_level: "E4",
    min_proof_level: "L3",
  },
} as const;

/** Build a FeatureGate from the runtime state of an in-process daemon. */
export interface BuildFeatureGateArgs {
  features: Iterable<string>;
  enforcementLevel: EnforcementLevel;
  proofLevelFloor: ProofLevel;
  bridges: Iterable<string>;
  anchors: Iterable<string>;
}

export function buildProfileFeatureGate(args: BuildFeatureGateArgs): ProfileFeatureGate {
  return {
    features: new Set(args.features),
    enforcementLevel: args.enforcementLevel,
    proofLevelFloor: args.proofLevelFloor,
    bridges: new Set(args.bridges),
    anchors: new Set(args.anchors),
  };
}
