//! Trust-level overlays — Rust mirror of
//! `tools/tf-types-ts/src/core/trust-overlay.ts`. See that file for the
//! design rationale; this module exists so the daemon, RPC server, and
//! conformance vectors can produce identical TrustLevel decisions in
//! both languages.

use serde::{Deserialize, Serialize};

use crate::generated::{ActorIdentity, ProofLevel, TrustLevel};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PostureContext {
    #[serde(default)]
    pub hardware_backed: bool,
    #[serde(default)]
    pub attestation_verified: bool,
    #[serde(default)]
    pub proof_level_achieved: Option<ProofLevel>,
    #[serde(default)]
    pub recent_verification_seconds: Option<u64>,
    #[serde(default)]
    pub stale_after_seconds: Option<u64>,
    #[serde(default)]
    pub quorum_approvers_at_least: Option<u32>,
    #[serde(default)]
    pub untrusted_relay_path: bool,
    #[serde(default)]
    pub recently_revoked: bool,
    #[serde(default)]
    pub publicly_anchored: bool,
    #[serde(default)]
    pub compliance_attested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustOverlayResult {
    pub level: TrustLevel,
    pub reasons: Vec<String>,
}

const ORDER: [TrustLevel; 8] = [
    TrustLevel::T0,
    TrustLevel::T1,
    TrustLevel::T2,
    TrustLevel::T3,
    TrustLevel::T4,
    TrustLevel::T5,
    TrustLevel::T6,
    TrustLevel::T7,
];

fn rank(level: &TrustLevel) -> usize {
    ORDER.iter().position(|t| t == level).unwrap_or(0)
}

fn level_from_rank(r: usize) -> TrustLevel {
    let clamped = r.min(ORDER.len() - 1);
    ORDER[clamped].clone()
}

pub fn compose_trust_level(
    identity: &ActorIdentity,
    posture: &PostureContext,
) -> TrustOverlayResult {
    let mut reasons = Vec::new();
    let base = highest_level(&identity.trust_levels);
    let mut r = rank(&base);
    reasons.push(format!("base={}", trust_level_str(&base)));

    if posture.recently_revoked {
        reasons.push("revoked → T0".into());
        return TrustOverlayResult {
            level: TrustLevel::T0,
            reasons,
        };
    }
    let stale = posture.stale_after_seconds.unwrap_or(86_400);
    if let Some(seen) = posture.recent_verification_seconds {
        if seen > stale {
            reasons.push(format!("stale ({}s > {}s) → T0", seen, stale));
            return TrustOverlayResult {
                level: TrustLevel::T0,
                reasons,
            };
        }
    }

    if posture.hardware_backed && r < rank(&TrustLevel::T4) {
        r = rank(&TrustLevel::T4);
        reasons.push("hardware-backed → ≥T4".into());
    }
    if posture.attestation_verified && r < rank(&TrustLevel::T4) {
        r = rank(&TrustLevel::T4);
        reasons.push("attestation verified → ≥T4".into());
    }
    if posture.quorum_approvers_at_least.unwrap_or(0) >= 2 && r < rank(&TrustLevel::T5) {
        r = rank(&TrustLevel::T5);
        reasons.push("quorum ≥2 → ≥T5".into());
    }
    if posture.publicly_anchored && r < rank(&TrustLevel::T6) {
        r = rank(&TrustLevel::T6);
        reasons.push("publicly anchored → ≥T6".into());
    }
    if posture.compliance_attested && r < rank(&TrustLevel::T7) {
        r = rank(&TrustLevel::T7);
        reasons.push("compliance attestation → T7".into());
    }
    if let Some(level) = &posture.proof_level_achieved {
        if let Some(target) = proof_level_minimum_trust(level) {
            if rank(&target) > r {
                r = rank(&target);
                reasons.push(format!(
                    "proof level {} → ≥{}",
                    proof_level_str(level),
                    trust_level_str(&target)
                ));
            }
        }
    }

    if posture.untrusted_relay_path && r > 0 {
        r -= 1;
        reasons.push("untrusted relay path → -1".into());
    }

    TrustOverlayResult {
        level: level_from_rank(r),
        reasons,
    }
}

fn highest_level(levels: &[TrustLevel]) -> TrustLevel {
    if levels.is_empty() {
        return TrustLevel::T0;
    }
    let mut best = TrustLevel::T0;
    for l in levels {
        if rank(l) > rank(&best) {
            best = l.clone();
        }
    }
    best
}

fn proof_level_minimum_trust(level: &ProofLevel) -> Option<TrustLevel> {
    match level {
        ProofLevel::L0 => Some(TrustLevel::T0),
        ProofLevel::L1 => Some(TrustLevel::T1),
        ProofLevel::L2 => Some(TrustLevel::T2),
        ProofLevel::L3 => Some(TrustLevel::T3),
        ProofLevel::L4 => Some(TrustLevel::T6),
        ProofLevel::L5 => Some(TrustLevel::T7),
    }
}

fn trust_level_str(level: &TrustLevel) -> &'static str {
    match level {
        TrustLevel::T0 => "T0",
        TrustLevel::T1 => "T1",
        TrustLevel::T2 => "T2",
        TrustLevel::T3 => "T3",
        TrustLevel::T4 => "T4",
        TrustLevel::T5 => "T5",
        TrustLevel::T6 => "T6",
        TrustLevel::T7 => "T7",
    }
}

fn proof_level_str(level: &ProofLevel) -> &'static str {
    match level {
        ProofLevel::L0 => "L0",
        ProofLevel::L1 => "L1",
        ProofLevel::L2 => "L2",
        ProofLevel::L3 => "L3",
        ProofLevel::L4 => "L4",
        ProofLevel::L5 => "L5",
    }
}
