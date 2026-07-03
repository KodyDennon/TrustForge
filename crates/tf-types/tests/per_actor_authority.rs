#![allow(clippy::needless_borrows_for_generic_args)]
//! Per-actor authority parity tests — Rust mirror of
//! `tools/tf-types-ts/tests/per-actor-authority.test.ts`.

use serde_json::json;
use tf_types::actor_id::derive_peer_actor;
use tf_types::guard::{AgentGuard, GuardQuery};

#[test]
fn derive_peer_actor_returns_canonical_thumbprint_uri() {
    let pub_a = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let uri = derive_peer_actor(&pub_a).expect("derive");
    assert!(uri.starts_with("tf:actor:process:key/"));
    let thumb = uri.trim_start_matches("tf:actor:process:key/");
    assert_eq!(thumb.len(), 16);
    assert!(thumb.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn derive_peer_actor_matches_ts_for_known_key() {
    // RFC 8032 vector 1 public key.
    let pub_a = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    // Computed once with sha256(pub_a).slice(0,8) -> hex
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&pub_a);
    let thumb_expected: String = digest[..8].iter().map(|b| format!("{:02x}", b)).collect();
    let uri = derive_peer_actor(&pub_a).expect("derive");
    assert_eq!(uri, format!("tf:actor:process:key/{}", thumb_expected));
}

#[test]
fn derive_peer_actor_rejects_wrong_length() {
    assert!(derive_peer_actor(&[0u8; 16]).is_err());
}

fn contract() -> serde_json::Value {
    json!({
      "contract_version": "1",
      "spec_version": "TF-0006-draft",
      "project": "actor-scope",
      "trust_domain": "example.com",
      "actions": [
        {
          "name": "fs.write",
          "risk": "R0",
          "approval": "none",
          "reversible": true,
          "allow_actors": ["tf:actor:process:key/*"],
        },
        {
          "name": "fs.read",
          "risk": "R0",
          "approval": "none",
          "reversible": true,
          "deny_actors": ["tf:actor:agent:evil.example/*"],
        },
        {
          "name": "admin.shutdown",
          "risk": "R5",
          "approval": "quorum",
          "reversible": false,
          "allow_actors": ["tf:actor:human:example.com/admin-1"],
        },
      ],
    })
}

#[test]
fn allow_actors_permits_matching_thumbprint() {
    let guard = AgentGuard::from_contract(&contract());
    let q = GuardQuery {
        actor: Some("tf:actor:process:key/abcdef0123456789".into()),
        actor_claim: None,
        action: "fs.write".into(),
        target: None,
    };
    let d = guard.check(&q);
    assert_eq!(d.kind(), "allow");
}

#[test]
fn allow_actors_denies_non_matching_actor() {
    let guard = AgentGuard::from_contract(&contract());
    let q = GuardQuery {
        actor: Some("tf:actor:agent:other.example/x".into()),
        actor_claim: None,
        action: "fs.write".into(),
        target: None,
    };
    let d = guard.check(&q);
    assert_eq!(d.kind(), "deny");
}

#[test]
fn deny_actors_blocks_even_when_allow_actors_would_permit() {
    let guard = AgentGuard::from_contract(&contract());
    let q = GuardQuery {
        actor: Some("tf:actor:agent:evil.example/scout".into()),
        actor_claim: None,
        action: "fs.read".into(),
        target: None,
    };
    let d = guard.check(&q);
    assert_eq!(d.kind(), "deny");
}

#[test]
fn matches_against_actor_claim_as_well_as_canonical() {
    let guard = AgentGuard::from_contract(&contract());
    let q = GuardQuery {
        actor: Some("tf:actor:process:key/0011223344556677".into()),
        actor_claim: Some("tf:actor:human:example.com/admin-1".into()),
        action: "admin.shutdown".into(),
        target: None,
    };
    let d = guard.check(&q);
    assert_eq!(d.kind(), "approval-required");
}

#[test]
fn missing_actor_for_allow_restricted_action_fails_closed() {
    let guard = AgentGuard::from_contract(&contract());
    let q = GuardQuery {
        actor: None,
        actor_claim: None,
        action: "admin.shutdown".into(),
        target: None,
    };
    let d = guard.check(&q);
    assert_eq!(d.kind(), "deny");
}

#[test]
fn actions_without_actor_lists_remain_open() {
    let open = json!({
      "contract_version": "1",
      "spec_version": "TF-0006-draft",
      "project": "open",
      "trust_domain": "example.com",
      "actions": [{ "name": "tf.ping", "risk": "R0", "approval": "none", "reversible": true }],
    });
    let guard = AgentGuard::from_contract(&open);
    let q = GuardQuery {
        actor: Some("tf:actor:process:key/anything".into()),
        actor_claim: None,
        action: "tf.ping".into(),
        target: None,
    };
    let d = guard.check(&q);
    assert_eq!(d.kind(), "allow");
}
