//! Rust semantics tests mirroring `tools/tf-types-ts/tests/authority.test.ts`.
//! Shares `conformance/semantics-vectors.yaml` as a parity layer.

use tf_types::capability::{constraints_satisfied, intersect_constraints, EvalContext};
use tf_types::delegation::walk_chain;
use tf_types::envelope::{validate_envelope_shape, EnvelopeIssue};
use tf_types::generated::common::{
    Capability, Constraint, DelegationLink, DelegationLink_Redelegation, SignatureEnvelope,
};
use tf_types::generated::revocation::{Revocation, Revocation_TargetKind};
use tf_types::revocation::RevocationIndex;

fn now() -> &'static str {
    "2026-04-24T12:00:00Z"
}

#[test]
fn constraints_time_window_in_range() {
    let c = Constraint::TimeWindow {
        from: Some("2026-01-01T00:00:00Z".into()),
        until: "2026-12-31T00:00:00Z".into(),
    };
    let ctx = EvalContext {
        now: now().into(),
        ..Default::default()
    };
    assert!(constraints_satisfied(&[c], &ctx));
}

#[test]
fn constraints_time_window_past_end() {
    let c = Constraint::TimeWindow {
        from: None,
        until: "2020-01-01T00:00:00Z".into(),
    };
    let ctx = EvalContext {
        now: now().into(),
        ..Default::default()
    };
    assert!(!constraints_satisfied(&[c], &ctx));
}

#[test]
fn constraints_target_glob() {
    let c = Constraint::Target {
        patterns: vec!["src/**".into()],
    };
    let hit = EvalContext {
        now: now().into(),
        target: Some("src/main.ts".into()),
        ..Default::default()
    };
    let miss = EvalContext {
        now: now().into(),
        target: Some("other/main.ts".into()),
        ..Default::default()
    };
    assert!(constraints_satisfied(&[c.clone()], &hit));
    assert!(!constraints_satisfied(&[c], &miss));
}

#[test]
fn constraints_session_match() {
    let c = Constraint::Session {
        session_id: "s1".into(),
    };
    let ctx_match = EvalContext {
        now: now().into(),
        session_id: Some("s1".into()),
        ..Default::default()
    };
    let ctx_mismatch = EvalContext {
        now: now().into(),
        session_id: Some("s2".into()),
        ..Default::default()
    };
    assert!(constraints_satisfied(&[c.clone()], &ctx_match));
    assert!(!constraints_satisfied(&[c], &ctx_mismatch));
}

#[test]
fn constraints_quorum_threshold() {
    let c = Constraint::Quorum {
        quorum: 2,
        of: vec![
            "tf:actor:human:example.com/a".into(),
            "tf:actor:human:example.com/b".into(),
        ],
    };
    let ok = EvalContext {
        now: now().into(),
        approver_count: Some(2),
        ..Default::default()
    };
    let bad = EvalContext {
        now: now().into(),
        approver_count: Some(1),
        ..Default::default()
    };
    assert!(constraints_satisfied(&[c.clone()], &ok));
    assert!(!constraints_satisfied(&[c], &bad));
}

#[test]
fn intersect_tightens_time_windows() {
    let a = Constraint::TimeWindow {
        from: Some("2026-01-01T00:00:00Z".into()),
        until: "2026-12-31T00:00:00Z".into(),
    };
    let b = Constraint::TimeWindow {
        from: Some("2026-03-01T00:00:00Z".into()),
        until: "2026-06-30T00:00:00Z".into(),
    };
    let r = intersect_constraints(&[a], &[b]);
    assert_eq!(r.len(), 1);
    match &r[0] {
        Constraint::TimeWindow { from, until } => {
            assert_eq!(from.as_deref(), Some("2026-03-01T00:00:00Z"));
            assert_eq!(until, "2026-06-30T00:00:00Z");
        }
        _ => panic!("expected time_window"),
    }
}

#[test]
fn intersect_rates_takes_smaller_cap() {
    let a = Constraint::Rate {
        max_per_window: 100,
        window_seconds: 60,
    };
    let b = Constraint::Rate {
        max_per_window: 50,
        window_seconds: 120,
    };
    let r = intersect_constraints(&[a], &[b]);
    match &r[0] {
        Constraint::Rate {
            max_per_window,
            window_seconds,
        } => {
            assert_eq!(*max_per_window, 50);
            assert_eq!(*window_seconds, 60);
        }
        _ => panic!("expected rate"),
    }
}

#[test]
fn chain_single_step_valid() {
    let chain = vec![DelegationLink {
        delegator: "tf:actor:human:example.com/a".into(),
        delegate: "tf:actor:agent:example.com/b".into(),
        capabilities: vec![Capability {
            name: "file.read".into(),
            risk: tf_types::generated::common::RiskClass::R0,
            proof_required: None,
            approval: None,
            constraints: None,
            single_use: None,
            delegable: None,
            revocable: None,
            offline_valid: None,
            expires_at: None,
        }],
        constraints: None,
        expires_at: None,
        redelegation: None,
        proof_ref: None,
    }];
    let r = walk_chain(&chain, now());
    assert!(r.valid);
}

#[test]
fn chain_expired_step_breaks() {
    let chain = vec![DelegationLink {
        delegator: "tf:actor:human:example.com/a".into(),
        delegate: "tf:actor:agent:example.com/b".into(),
        capabilities: vec![Capability {
            name: "file.read".into(),
            risk: tf_types::generated::common::RiskClass::R0,
            proof_required: None,
            approval: None,
            constraints: None,
            single_use: None,
            delegable: None,
            revocable: None,
            offline_valid: None,
            expires_at: None,
        }],
        constraints: None,
        expires_at: Some("2020-01-01T00:00:00Z".into()),
        redelegation: None,
        proof_ref: None,
    }];
    let r = walk_chain(&chain, now());
    assert!(!r.valid);
    assert_eq!(r.broken_step, Some(0));
}

#[test]
fn chain_no_redelegation_blocks_next() {
    use tf_types::generated::common::RiskClass;
    let cap = Capability {
        name: "file.read".into(),
        risk: RiskClass::R0,
        proof_required: None,
        approval: None,
        constraints: None,
        single_use: None,
        delegable: None,
        revocable: None,
        offline_valid: None,
        expires_at: None,
    };
    let chain = vec![
        DelegationLink {
            delegator: "tf:actor:human:example.com/root".into(),
            delegate: "tf:actor:organization:example.com".into(),
            capabilities: vec![cap.clone()],
            constraints: None,
            expires_at: None,
            redelegation: Some(DelegationLink_Redelegation {
                allowed: false,
                max_depth: None,
            }),
            proof_ref: None,
        },
        DelegationLink {
            delegator: "tf:actor:organization:example.com".into(),
            delegate: "tf:actor:agent:example.com/a".into(),
            capabilities: vec![cap],
            constraints: None,
            expires_at: None,
            redelegation: None,
            proof_ref: None,
        },
    ];
    let r = walk_chain(&chain, now());
    assert!(!r.valid);
    assert_eq!(r.broken_step, Some(1));
}

#[test]
fn revocation_detects_after_effective_time() {
    let rev = Revocation {
        revocation_version: tf_types::generated::revocation::Revocation_RevocationVersion::V1,
        id: "r1".into(),
        target_id: "tok-1".into(),
        target_kind: Revocation_TargetKind::Capability,
        effective_at: "2026-04-24T15:00:00Z".into(),
        reason: None,
        reinstatement_possible: None,
        issuer: "tf:actor:organization:example.com".into(),
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: "tf:actor:organization:example.com".into(),
            signature: "AAAA".into(),
            hash_alg: None,
            alt_algorithm: None,
            alt_signature: None,
        },
    };
    let idx = RevocationIndex::from_slice(&[rev]);
    assert!(idx.is_revoked("tok-1", &Revocation_TargetKind::Capability, "2026-04-24T16:00:00Z"));
    assert!(!idx.is_revoked("tok-1", &Revocation_TargetKind::Capability, "2026-04-24T14:00:00Z"));
    assert!(!idx.is_revoked("tok-1", &Revocation_TargetKind::Actor, "2026-04-24T16:00:00Z"));
}

#[test]
fn envelope_accepts_well_formed() {
    let e = SignatureEnvelope {
        algorithm: "ed25519".into(),
        signer: "tf:actor:organization:example.com".into(),
        signature: "dGVzdC1zaWc=".into(),
        hash_alg: None,
        alt_algorithm: None,
        alt_signature: None,
    };
    let r = validate_envelope_shape(&e);
    assert!(r.ok);
    assert!(r.issues.iter().all(|i| matches!(i, EnvelopeIssue::UnknownAlgorithm { .. } | EnvelopeIssue::UnknownAltAlgorithm { .. }) || r.ok));
}

#[test]
fn envelope_flags_invalid_base64() {
    let e = SignatureEnvelope {
        algorithm: "ed25519".into(),
        signer: "tf:actor:organization:example.com".into(),
        signature: "not base64!!".into(),
        hash_alg: None,
        alt_algorithm: None,
        alt_signature: None,
    };
    let r = validate_envelope_shape(&e);
    assert!(!r.ok);
    assert!(r
        .issues
        .iter()
        .any(|i| matches!(i, EnvelopeIssue::InvalidBase64 { .. })));
}

#[test]
fn envelope_warns_unknown_algorithm_but_ok() {
    let e = SignatureEnvelope {
        algorithm: "snake-oil".into(),
        signer: "tf:actor:organization:example.com".into(),
        signature: "AAAA".into(),
        hash_alg: None,
        alt_algorithm: None,
        alt_signature: None,
    };
    let r = validate_envelope_shape(&e);
    assert!(r.ok);
    assert!(r
        .issues
        .iter()
        .any(|i| matches!(i, EnvelopeIssue::UnknownAlgorithm { .. })));
}
