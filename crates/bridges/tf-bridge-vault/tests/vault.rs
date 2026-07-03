#![allow(clippy::useless_vec)]
//! Tests for the Vault bridge — uses a stub `VaultLookup` to exercise
//! the actor-translation path without hitting a real Vault instance.

use async_trait::async_trait;
use tf_bridge_vault::{
    vault_policies_to_capabilities, vault_secret_path_to_capability, vault_token_to_actor,
    VaultBridgeError, VaultLookup, VaultTokenInfo,
};
use tf_types::generated::{ActorType, Constraint, RiskClass, TrustLevel};

struct StubLookup {
    info: VaultTokenInfo,
}

#[async_trait]
impl VaultLookup for StubLookup {
    async fn lookup_self(&self) -> Result<VaultTokenInfo, VaultBridgeError> {
        Ok(self.info.clone())
    }
}

struct ErroringLookup;

#[async_trait]
impl VaultLookup for ErroringLookup {
    async fn lookup_self(&self) -> Result<VaultTokenInfo, VaultBridgeError> {
        Err(VaultBridgeError::Rejected("forbidden".into()))
    }
}

#[tokio::test]
async fn token_to_actor_default_policy() {
    let info = VaultTokenInfo {
        accessor: "AbCdEf123".into(),
        display_name: "ci-runner".into(),
        entity_id: Some("entity-1".into()),
        policies: vec!["default".into()],
        ttl: 3600,
        renewable: true,
        orphan: false,
        path: "auth/approle/login".into(),
        namespace: None,
    };
    let lookup = StubLookup { info: info.clone() };
    let (actor, returned) = vault_token_to_actor(&lookup, "prod-cluster").await.unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:vault.prod-cluster/root/AbCdEf123"
    );
    assert_eq!(actor.actor_type, ActorType::Service);
    assert_eq!(actor.trust_levels, vec![TrustLevel::T3]);
    assert_eq!(actor.authority_roots[0].id, "vault-cluster:prod-cluster");
    assert_eq!(returned, info);
}

#[tokio::test]
async fn token_to_actor_with_namespace() {
    let info = VaultTokenInfo {
        accessor: "tokenAccessor1".into(),
        display_name: "x".into(),
        entity_id: None,
        policies: vec![],
        ttl: 60,
        renewable: false,
        orphan: false,
        path: "x".into(),
        namespace: Some("team-payments".into()),
    };
    let lookup = StubLookup { info };
    let (actor, _) = vault_token_to_actor(&lookup, "us-east-1").await.unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:vault.us-east-1/team-payments/tokenAccessor1"
    );
}

#[tokio::test]
async fn token_to_actor_propagates_lookup_error() {
    let lookup = ErroringLookup;
    let err = vault_token_to_actor(&lookup, "x").await.unwrap_err();
    assert!(matches!(err, VaultBridgeError::Rejected(_)));
}

#[tokio::test]
async fn token_to_actor_rejects_empty_accessor() {
    let info = VaultTokenInfo {
        accessor: String::new(),
        display_name: "x".into(),
        entity_id: None,
        policies: vec![],
        ttl: 0,
        renewable: false,
        orphan: false,
        path: "x".into(),
        namespace: None,
    };
    let lookup = StubLookup { info };
    let err = vault_token_to_actor(&lookup, "x").await.unwrap_err();
    assert!(matches!(err, VaultBridgeError::Rejected(_)));
}

#[test]
fn secret_path_to_capability_simple() {
    let cap = vault_secret_path_to_capability("kv/data", "app/db/password");
    assert_eq!(cap.name, "vault.kv.read");
    assert_eq!(cap.risk, RiskClass::R2);
    let cs = cap.constraints.unwrap();
    match &cs[0] {
        Constraint::Target { patterns } => {
            assert_eq!(patterns[0], "kv/data/app/db/password");
        }
        _ => panic!("expected target"),
    }
}

#[test]
fn secret_path_to_capability_empty_path() {
    let cap = vault_secret_path_to_capability("kv", "");
    let cs = cap.constraints.unwrap();
    match &cs[0] {
        Constraint::Target { patterns } => {
            assert_eq!(patterns[0], "kv/");
        }
        _ => panic!("expected target"),
    }
}

#[test]
fn policies_to_capabilities_handles_root_default_and_custom() {
    let caps = vault_policies_to_capabilities(&vec![
        "root".into(),
        "default".into(),
        "DBOps".into(),
        "ReadOnly".into(),
    ]);
    assert_eq!(caps.len(), 4);
    assert_eq!(caps[0].name, "vault.*");
    assert_eq!(caps[0].risk, RiskClass::R5);
    assert_eq!(caps[1].name, "vault.token.*");
    assert_eq!(caps[1].risk, RiskClass::R1);
    assert_eq!(caps[2].name, "vault.policy.dbops");
    assert_eq!(caps[3].name, "vault.policy.readonly");
}
