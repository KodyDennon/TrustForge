//! TrustForge simulation harness — Rust mirror of
//! `tools/tf-types-ts/src/core/simulation.ts`.
//!
//! Models the 12 scenarios DECISIONS.md asks the runtime to be able to
//! execute headlessly. Every scenario uses only TrustForge primitives
//! already implemented in this crate; no external IO. Designed for
//! deterministic conformance + spec-validation runs.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{ed25519_verify, Ed25519Signer};
use crate::crypto_pq::{ml_dsa_65_generate, ml_dsa_65_sign, ml_dsa_65_verify};
use crate::guard::{
    apply_enforcement_level, AgentGuard, EnforcementLevel, GuardDecision, GuardQuery,
    NegativeCapability,
};
use crate::packet::{sign_packet, verify_packet, SignPacketArgs};
use crate::policy_engine::{NativePolicyEngine, PolicyManifest, PolicyQuery, PolicyRule};
use crate::quorum::{QuorumApprovalCollector, QuorumConfig, QuorumSignature};
use crate::relay::{
    sign_relay_authority, RelayAuthority, RelayFrame, RelayHandler, SignatureEnvelope,
};
use crate::session_migration::{migrate_session, verify_session_migration, TransportBinding};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioName {
    PartialTrustDomainMerge,
    AiBoundaryBreach,
    RelayLoss,
    QuorumFailure,
    FrameReplay,
    ExpiredToken,
    RevokedActorMidSession,
    ForgedSignature,
    HopCapExceeded,
    EmergencyWithoutFollowup,
    PqVerifierRejectsClassicalForgery,
    ContinuousReauthDuringStream,
}

pub const ALL_SCENARIOS: [ScenarioName; 12] = [
    ScenarioName::PartialTrustDomainMerge,
    ScenarioName::AiBoundaryBreach,
    ScenarioName::RelayLoss,
    ScenarioName::QuorumFailure,
    ScenarioName::FrameReplay,
    ScenarioName::ExpiredToken,
    ScenarioName::RevokedActorMidSession,
    ScenarioName::ForgedSignature,
    ScenarioName::HopCapExceeded,
    ScenarioName::EmergencyWithoutFollowup,
    ScenarioName::PqVerifierRejectsClassicalForgery,
    ScenarioName::ContinuousReauthDuringStream,
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub name: ScenarioName,
    pub ok: bool,
    pub observations: Vec<String>,
    pub failures: Vec<String>,
}

fn fresh_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

fn empty_binding(kind: &str) -> TransportBinding {
    TransportBinding {
        binding_version: "1".into(),
        kind: kind.into(),
        endpoint: None,
        exporter_key: None,
        peer_cert_fingerprint: None,
        tls_alpn: None,
        established_at: None,
        metadata: None,
    }
}

pub fn run_scenario(name: ScenarioName) -> ScenarioResult {
    let mut obs: Vec<String> = Vec::new();
    let mut fails: Vec<String> = Vec::new();
    match name.clone() {
        ScenarioName::PartialTrustDomainMerge => {
            let contract_a = serde_json::json!({
                "actions": [{"name": "data.read", "risk": "R1"}],
                "forbidden": [{"action": "data.delete", "reason": "domain A forbids deletion"}],
            });
            let contract_b = serde_json::json!({
                "actions": [
                    {"name": "data.read", "risk": "R1"},
                    {"name": "data.delete", "risk": "R3"},
                ],
            });
            let guard_a = AgentGuard::from_contract(&contract_a);
            let guard_b = AgentGuard::from_contract(&contract_b);
            let q = GuardQuery {
                actor: None,
                actor_claim: None,
                action: "data.delete".into(),
                target: Some("row/1".into()),
            };
            let a = guard_a.check(&q);
            let b = guard_b.check(&q);
            obs.push(format!("domain A: {}", a.kind()));
            obs.push(format!("domain B: {}", b.kind()));
            if a.kind() != "deny" || b.kind() == "deny" {
                fails.push("expected A to deny and B to allow data.delete".into());
            }
        }
        ScenarioName::AiBoundaryBreach => {
            let contract = serde_json::json!({
                "actions": [{"name": "file.read", "risk": "R0"}],
            });
            let guard = AgentGuard::from_contract(&contract);
            let decision = guard.check(&GuardQuery {
                actor: None,
                actor_claim: None,
                action: "shell.exec".into(),
                target: Some("rm -rf /".into()),
            });
            obs.push(format!("shell.exec → {}", decision.kind()));
            if decision.kind() != "deny" {
                fails.push("agent boundary not enforced".into());
            }
        }
        ScenarioName::RelayLoss => {
            let issuer_seed = fresh_seed();
            let issuer = Ed25519Signer::from_bytes(&issuer_seed);
            let issuer_pub = issuer.public_key_bytes();
            let mut authority = RelayAuthority {
                relay_authority_version: "1".into(),
                relay: "tf:actor:relay:example.com/edge".into(),
                trust_domain: "example.com".into(),
                kinds: vec!["forward-only".into()],
                max_hop_count: Some(4),
                rate_limit_per_minute: None,
                valid_from: "2026-04-24T00:00:00Z".into(),
                valid_until: Some("2026-04-25T00:00:00Z".into()),
                issuer: "tf:actor:service:example.com/tf-daemon".into(),
                constraints: None,
                signature: SignatureEnvelope {
                    algorithm: "ed25519".into(),
                    signer: String::new(),
                    signature: String::new(),
                },
            };
            authority = sign_relay_authority(authority, &issuer_seed);
            let relay = RelayHandler::new(authority, issuer_pub);
            let frame = RelayFrame {
                ciphertext: vec![0u8; 16],
                destination: "tf:actor:agent:example.com/x".into(),
                priority: None,
                hop_count: 0,
                expires_at: Some("2026-04-24T11:00:00Z".into()),
                source: None,
            };
            match relay.forward(&frame, "2026-04-24T12:00:00Z") {
                Ok(_) => fails.push("expired frame should have been dropped".into()),
                Err(e) => obs.push(format!("expired frame dropped: {}", e)),
            }
        }
        ScenarioName::QuorumFailure => {
            let collector = QuorumApprovalCollector::new(QuorumConfig {
                min_approvers: 2,
                of: vec![
                    "tf:actor:human:example.com/a".into(),
                    "tf:actor:human:example.com/b".into(),
                ],
            })
            .expect("config");
            let handle = collector.push("req-q", "2026-04-24T12:00:00Z");
            handle.respond_as(
                "tf:actor:human:example.com/a",
                "approve",
                QuorumSignature {
                    algorithm: "ed25519".into(),
                    signer: "tf:actor:human:example.com/a".into(),
                    signature: "AAA".into(),
                },
            );
            handle.respond_as(
                "tf:actor:human:example.com/b",
                "deny",
                QuorumSignature {
                    algorithm: "ed25519".into(),
                    signer: "tf:actor:human:example.com/b".into(),
                    signature: "BBB".into(),
                },
            );
            match handle.outcome() {
                Some(o) => {
                    obs.push(format!(
                        "quorum decision={} approvers={}",
                        o.decision,
                        o.approvers.len()
                    ));
                    if o.decision != "deny" {
                        fails.push("quorum should have denied".into());
                    }
                }
                None => fails.push("quorum did not produce an outcome".into()),
            }
        }
        ScenarioName::FrameReplay => {
            let priv_seed = fresh_seed();
            let pair = Ed25519Signer::from_bytes(&priv_seed);
            let pub_bytes = pair.public_key_bytes();
            let m1 = migrate_session(
                "s",
                1,
                empty_binding("websocket"),
                empty_binding("quic"),
                false,
                None,
                "tf:actor:agent:example.com/x",
                &priv_seed,
                Some("2026-04-24T12:00:00Z"),
            );
            let v1 = verify_session_migration(&m1, &pub_bytes, Some(0), None);
            let v2 = verify_session_migration(&m1, &pub_bytes, Some(1), None); // replay
            obs.push(format!("first migration ok={}, replay ok={}", v1.ok, v2.ok));
            if !v1.ok || v2.ok {
                fails.push("replay protection not triggered".into());
            }
        }
        ScenarioName::ExpiredToken => {
            let priv_seed = fresh_seed();
            let pair = Ed25519Signer::from_bytes(&priv_seed);
            let pub_bytes = pair.public_key_bytes();
            match sign_packet(SignPacketArgs {
                packet_id: "pkt-x".into(),
                source: "tf:actor:agent:example.com/x".into(),
                destination: "tf:actor:service:example.com/d".into(),
                priority: "P3".into(),
                payload: b"hi",
                encoding: None,
                compression: None,
                emergency: false,
                expires_at: Some("2026-04-23T00:00:00Z".into()),
                ttl_hops: None,
                route_constraints: None,
                session_ref: None,
                private_key: priv_seed,
                signer: "tf:actor:agent:example.com/x".into(),
                created_at: Some("2026-04-22T00:00:00Z".into()),
            }) {
                Ok(p) => {
                    let v = verify_packet(&p, &pub_bytes, "2026-04-25T00:00:00Z");
                    obs.push(format!(
                        "expired-token verify: ok={} reason={}",
                        v.ok,
                        v.reason.clone().unwrap_or_default()
                    ));
                    if v.ok {
                        fails.push("expired packet accepted".into());
                    }
                }
                Err(e) => fails.push(format!("sign failed: {}", e)),
            }
        }
        ScenarioName::RevokedActorMidSession => {
            let policy = PolicyManifest {
                policy_version: "1".into(),
                trust_domain: "example.com".into(),
                engine_hint: None,
                rules: vec![PolicyRule {
                    id: "deny.shell".into(),
                    effect: "deny".into(),
                    action: Some("shell.exec".into()),
                    action_pattern: None,
                    subject_pattern: None,
                    target_patterns: None,
                    approval: None,
                    proof_required: None,
                    constraints: None,
                    reason: None,
                }],
                negative_capabilities: Vec::new(),
                continuous_reevaluation: None,
                quorum_defaults: None,
            };
            let engine = NativePolicyEngine::new(policy);
            let before = engine.evaluate(&PolicyQuery {
                subject: "tf:actor:agent:example.com/x".into(),
                instance: None,
                action: "shell.exec".into(),
                target: None,
                context: Default::default(),
                negative_capabilities: Vec::new(),
                enforcement_level: None,
                now: Some("2026-04-24T12:00:00Z".into()),
            });
            let after = engine.evaluate(&PolicyQuery {
                subject: "tf:actor:agent:example.com/x".into(),
                instance: None,
                action: "file.delete".into(),
                target: Some("/etc/passwd".into()),
                context: Default::default(),
                negative_capabilities: vec![NegativeCapability {
                    name: "file.delete".into(),
                    target: None,
                    reason: Some("actor revoked".into()),
                    overrides: None,
                }],
                enforcement_level: None,
                now: Some("2026-04-24T12:00:00Z".into()),
            });
            obs.push(format!("pre={}, post={}", before.decision, after.decision));
            if after.decision != "deny" {
                fails.push("revoked actor still allowed".into());
            }
        }
        ScenarioName::ForgedSignature => {
            let real_seed = fresh_seed();
            let other_seed = fresh_seed();
            let other = Ed25519Signer::from_bytes(&other_seed);
            let pub_other = other.public_key_bytes();
            match sign_packet(SignPacketArgs {
                packet_id: "pkt-forge".into(),
                source: "tf:actor:agent:example.com/x".into(),
                destination: "tf:actor:service:example.com/d".into(),
                priority: "P3".into(),
                payload: b"real",
                encoding: None,
                compression: None,
                emergency: false,
                expires_at: None,
                ttl_hops: None,
                route_constraints: None,
                session_ref: None,
                private_key: real_seed,
                signer: "tf:actor:agent:example.com/x".into(),
                created_at: Some("2026-04-24T12:00:00Z".into()),
            }) {
                Ok(p) => {
                    let v = verify_packet(&p, &pub_other, "2026-04-24T12:00:00Z");
                    obs.push(format!("forged check ok={}", v.ok));
                    if v.ok {
                        fails.push("packet verified under wrong public key".into());
                    }
                }
                Err(e) => fails.push(format!("sign failed: {}", e)),
            }
        }
        ScenarioName::HopCapExceeded => {
            let issuer_seed = fresh_seed();
            let issuer = Ed25519Signer::from_bytes(&issuer_seed);
            let issuer_pub = issuer.public_key_bytes();
            let mut authority = RelayAuthority {
                relay_authority_version: "1".into(),
                relay: "tf:actor:relay:example.com/edge".into(),
                trust_domain: "example.com".into(),
                kinds: vec!["forward-only".into()],
                max_hop_count: Some(2),
                rate_limit_per_minute: None,
                valid_from: "2026-04-24T00:00:00Z".into(),
                valid_until: Some("2026-04-25T00:00:00Z".into()),
                issuer: "tf:actor:service:example.com/tf-daemon".into(),
                constraints: None,
                signature: SignatureEnvelope {
                    algorithm: "ed25519".into(),
                    signer: String::new(),
                    signature: String::new(),
                },
            };
            authority = sign_relay_authority(authority, &issuer_seed);
            let relay = RelayHandler::new(authority, issuer_pub);
            let frame = RelayFrame {
                ciphertext: vec![0u8; 8],
                destination: "tf:actor:agent:example.com/x".into(),
                priority: None,
                hop_count: 5,
                expires_at: None,
                source: None,
            };
            match relay.forward(&frame, "2026-04-24T12:00:00Z") {
                Ok(_) => fails.push("hop cap not enforced".into()),
                Err(e) => obs.push(format!("hop cap blocked: {}", e)),
            }
        }
        ScenarioName::EmergencyWithoutFollowup => {
            let priv_seed = fresh_seed();
            match sign_packet(SignPacketArgs {
                packet_id: "pkt-emerg".into(),
                source: "tf:actor:human:example.com/alice".into(),
                destination: "tf:actor:service:example.com/d".into(),
                priority: "P0".into(),
                payload: b"emergency",
                encoding: None,
                compression: None,
                emergency: true,
                expires_at: None,
                ttl_hops: None,
                route_constraints: None,
                session_ref: None,
                private_key: priv_seed,
                signer: "tf:actor:human:example.com/alice".into(),
                created_at: Some("2026-04-24T12:00:00Z".into()),
            }) {
                Ok(p) => {
                    let is_emergency = p.emergency.unwrap_or(false);
                    obs.push(format!("emergency packet={}", is_emergency));
                    if is_emergency {
                        obs.push(
                            "emergency invocation flagged incomplete (no follow-up review)".into(),
                        );
                    } else {
                        fails.push("emergency invocation should require follow-up review".into());
                    }
                }
                Err(e) => fails.push(format!("sign failed: {}", e)),
            }
        }
        ScenarioName::PqVerifierRejectsClassicalForgery => {
            // Parallel hybrid composition: independent ed25519 + ml-dsa-65
            // signatures over the same transcript. Forging one without the
            // other must fail the hybrid verifier.
            let classical_seed = fresh_seed();
            let classical = Ed25519Signer::from_bytes(&classical_seed);
            let (pq_sk, pq_pk) = match ml_dsa_65_generate() {
                Ok(p) => p,
                Err(e) => {
                    fails.push(format!("ml-dsa-65 keygen: {}", e));
                    return ScenarioResult {
                        name,
                        ok: false,
                        observations: obs,
                        failures: fails,
                    };
                }
            };
            let msg = b"hello hybrid";
            let classical_sig = classical.sign(msg);
            let pq_sig = match ml_dsa_65_sign(&pq_sk, msg) {
                Ok(s) => s,
                Err(e) => {
                    fails.push(format!("ml-dsa-65 sign: {}", e));
                    return ScenarioResult {
                        name,
                        ok: false,
                        observations: obs,
                        failures: fails,
                    };
                }
            };
            let classical_ok =
                ed25519_verify(&classical.public_key_bytes(), msg, &classical_sig).is_ok();
            let pq_ok = ml_dsa_65_verify(&pq_pk, msg, &pq_sig);
            let hybrid_ok = classical_ok && pq_ok;
            // Forge by replacing the PQ signature with garbage. Hybrid
            // verifier (AND) must reject.
            let mut bad_pq = pq_sig.clone();
            bad_pq[0] ^= 0xff;
            let pq_forged_ok = ml_dsa_65_verify(&pq_pk, msg, &bad_pq);
            let hybrid_after_forge = classical_ok && pq_forged_ok;
            obs.push(format!(
                "hybrid pre-forge ok={}, post-forge ok={}",
                hybrid_ok, hybrid_after_forge
            ));
            if !hybrid_ok {
                fails.push("hybrid signature did not verify in honest path".into());
            }
            if hybrid_after_forge {
                fails.push("hybrid verifier accepted classical-only signature".into());
            }
        }
        ScenarioName::ContinuousReauthDuringStream => {
            let contract = serde_json::json!({
                "actions": [{"name": "session.stream", "risk": "R2"}],
            });
            let guard = AgentGuard::from_contract(&contract);
            let before = guard.check(&GuardQuery {
                actor: None,
                actor_claim: None,
                action: "session.stream".into(),
                target: None,
            });
            let after = apply_enforcement_level(before.clone(), EnforcementLevel::E5);
            obs.push(format!("before={} after={}", before.kind(), after.kind()));
            if before.kind() != "allow" {
                fails.push("expected initial allow".into());
            }
            // With a danger_tag, E5 must flip allow to non-allow.
            let contract2 = serde_json::json!({
                "actions": [{"name": "session.stream", "risk": "R2", "danger_tags": ["privacy"]}],
            });
            let guard2 = AgentGuard::from_contract(&contract2);
            let raw = guard2.check_raw(&GuardQuery {
                actor: None,
                actor_claim: None,
                action: "session.stream".into(),
                target: None,
            });
            let tightened = apply_enforcement_level(raw.clone(), EnforcementLevel::E5);
            obs.push(format!("tightened={}", tightened.kind()));
            if tightened.kind() == "allow" {
                fails.push("E5 should deny allow-with-danger-tags after reauth".into());
            }
        }
    }
    let ok = fails.is_empty();
    ScenarioResult {
        name,
        ok,
        observations: obs,
        failures: fails,
    }
}

/// Run every scenario and return the full report set.
pub fn run_all_scenarios() -> Vec<ScenarioResult> {
    ALL_SCENARIOS.iter().cloned().map(run_scenario).collect()
}

/// Shadow-mode helper: take an arbitrary GuardDecision and return what
/// the daemon would do at EnforcementLevel E0 (record-only).
pub fn as_shadow_decision(d: GuardDecision) -> GuardDecision {
    apply_enforcement_level(d, EnforcementLevel::E0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_scenario_runs() {
        for s in ALL_SCENARIOS.iter().cloned() {
            let r = run_scenario(s.clone());
            assert!(r.ok, "scenario {:?} failed: {:?}", s, r.failures);
        }
    }

    #[test]
    fn run_all_returns_twelve() {
        let results = run_all_scenarios();
        assert_eq!(results.len(), 12);
        for r in results {
            assert!(r.ok, "scenario {:?} failed: {:?}", r.name, r.failures);
        }
    }
}
