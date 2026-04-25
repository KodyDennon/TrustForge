/**
 * Trust-level overlays — compose a contextual `TrustLevel` from a base
 * `ActorIdentity` plus a runtime posture.
 *
 * DECISIONS.md "Composable and contextual trust": "Trust is not a single
 * static score." T-levels stored on an identity document are the floor;
 * the overlay can RAISE the level when posture proves stronger
 * authority, or LOWER the level when posture indicates weaker authority
 * (recent rekey gap, missing hardware backing, suspect relay path).
 *
 * The overlay is deterministic: same inputs → same output, in TS and
 * Rust. Cross-language parity is asserted in
 * `conformance/trust-overlay-vectors.yaml`.
 *
 * Base levels (TF-0001 / DECISIONS.md):
 *   T0 Unknown · T1 Self-claimed · T2 Locally trusted ·
 *   T3 Organization-issued · T4 Hardware-backed ·
 *   T5 Multi-party verified · T6 Publicly attestable ·
 *   T7 Regulated/compliance verified
 */

import type { ActorIdentity } from "../generated/actor-identity.js";
import type { TrustLevel, ProofLevel } from "../generated/_common.js";

export interface PostureContext {
  /** Hardware-backed key was used in the last successful auth handshake. */
  hardwareBacked?: boolean;
  /** Identity carries a verified attestation (e.g. WebAuthn packed
   *  attestation, TPM quote, SPIFFE federated bundle). */
  attestationVerified?: boolean;
  /** Highest proof level this actor produced in the last evaluation
   *  window. */
  proofLevelAchieved?: ProofLevel;
  /** Seconds since the last successful re-verification (handshake
   *  completion, rekey, or explicit reauth). */
  recentVerificationSeconds?: number;
  /** Maximum age before a previously-verified actor falls back to T0.
   *  Default 86400 (1 day). */
  staleAfterSeconds?: number;
  /** Quorum approvers that signed off on the actor's last decision.
   *  ≥2 raises the floor to T5. */
  quorumApproversAtLeast?: number;
  /** Set when the relay path between us and the actor cannot be
   *  audited end-to-end. Lowers the level by one step. */
  untrustedRelayPath?: boolean;
  /** Recent revocation event in the trust domain — degrades to T0. */
  recentlyRevoked?: boolean;
  /** Public anchor (transparency log, public CT, sigstore) saw the
   *  identity. Raises floor to T6 when present. */
  publiclyAnchored?: boolean;
  /** Compliance-grade attestation (FIPS, SOC, HIPAA, FedRAMP, etc.)
   *  attached to the identity. Raises floor to T7. */
  complianceAttested?: boolean;
}

export interface TrustOverlayResult {
  level: TrustLevel;
  /** Audit trail of every adjustment applied by the overlay. */
  reasons: string[];
}

const ORDER: TrustLevel[] = ["T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7"];

function rank(level: TrustLevel): number {
  return ORDER.indexOf(level);
}

function levelFromRank(r: number): TrustLevel {
  const clamped = Math.max(0, Math.min(ORDER.length - 1, r));
  return ORDER[clamped]!;
}

/** Compose the contextual trust level. Base level is the highest
 *  T-level on the identity document; the overlay raises or lowers it. */
export function composeTrustLevel(
  identity: ActorIdentity,
  posture: PostureContext = {},
): TrustOverlayResult {
  const reasons: string[] = [];
  // 1. Base = highest level on the identity.
  const base = highestLevel(identity.trust_levels);
  let r = rank(base);
  reasons.push(`base=${base}`);

  // 2. Hard-cap downward conditions.
  if (posture.recentlyRevoked) {
    reasons.push("revoked → T0");
    return { level: "T0", reasons };
  }
  const stale = posture.staleAfterSeconds ?? 86_400;
  if (
    posture.recentVerificationSeconds !== undefined &&
    posture.recentVerificationSeconds > stale
  ) {
    reasons.push(`stale (${posture.recentVerificationSeconds}s > ${stale}s) → T0`);
    return { level: "T0", reasons };
  }

  // 3. Posture-driven raises (each lifts the floor; we never lower below
  //    the base unless explicitly downgraded).
  if (posture.hardwareBacked && r < rank("T4")) {
    r = rank("T4");
    reasons.push("hardware-backed → ≥T4");
  }
  if (posture.attestationVerified && r < rank("T4")) {
    r = rank("T4");
    reasons.push("attestation verified → ≥T4");
  }
  if ((posture.quorumApproversAtLeast ?? 0) >= 2 && r < rank("T5")) {
    r = rank("T5");
    reasons.push(`quorum ≥2 → ≥T5`);
  }
  if (posture.publiclyAnchored && r < rank("T6")) {
    r = rank("T6");
    reasons.push("publicly anchored → ≥T6");
  }
  if (posture.complianceAttested && r < rank("T7")) {
    r = rank("T7");
    reasons.push("compliance attestation → T7");
  }
  if (posture.proofLevelAchieved) {
    const target = proofLevelMinimumTrust(posture.proofLevelAchieved);
    if (target && rank(target) > r) {
      r = rank(target);
      reasons.push(`proof level ${posture.proofLevelAchieved} → ≥${target}`);
    }
  }

  // 4. Soft-cap downward conditions.
  if (posture.untrustedRelayPath && r > 0) {
    r -= 1;
    reasons.push("untrusted relay path → -1");
  }

  return { level: levelFromRank(r), reasons };
}

function highestLevel(levels: TrustLevel[] | undefined): TrustLevel {
  if (!levels || levels.length === 0) return "T0";
  let best = "T0" as TrustLevel;
  for (const l of levels) {
    if (rank(l) > rank(best)) best = l;
  }
  return best;
}

/** L0 → T0, L1 → T1, L2 → T2, L3 → T3, L4 → T6, L5 → T7. The mapping is
 *  intentionally non-linear: an L4 encrypted evidence bundle is much
 *  closer to a public anchor than to plain organization-issued. */
function proofLevelMinimumTrust(level: ProofLevel): TrustLevel | undefined {
  switch (level) {
    case "L0":
      return "T0";
    case "L1":
      return "T1";
    case "L2":
      return "T2";
    case "L3":
      return "T3";
    case "L4":
      return "T6";
    case "L5":
      return "T7";
    default:
      return undefined;
  }
}
