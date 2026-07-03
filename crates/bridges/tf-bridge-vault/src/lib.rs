#![allow(clippy::useless_vec)]
//! TrustForge bridge for HashiCorp Vault.
//!
//! Two primary entry points:
//!
//! 1. [`vault_token_to_actor`] — given a `vaultrs::client::VaultClient`
//!    (or any client that exposes `auth/token/lookup-self`), translate
//!    the live token into a TrustForge `ActorIdentity`.
//!
//! 2. [`vault_secret_path_to_capability`] — translate a secret-mount +
//!    path into a TrustForge `Capability` that grants
//!    `vault.kv.read` against the path as a target glob.
//!
//! The bridge intentionally does not embed the secret itself — only the
//! authority to retrieve it. The daemon is responsible for actually
//! reading the secret when the policy engine grants the capability.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use tf_types::bridges::{Bridge, BridgeKind};
use tf_types::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    Capability, Constraint, RiskClass, TrustLevel,
};

#[derive(Debug, Error)]
pub enum VaultBridgeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("vault rejected token: {0}")]
    Rejected(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Lookup result from Vault's `auth/token/lookup-self` endpoint.
/// Subset — we only retain the fields used for actor projection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultTokenInfo {
    pub accessor: String,
    pub display_name: String,
    pub entity_id: Option<String>,
    pub policies: Vec<String>,
    pub ttl: u64,
    pub renewable: bool,
    pub orphan: bool,
    pub path: String,
    /// Cluster name from the lookup response, used as the trust domain.
    pub namespace: Option<String>,
}

/// Generic interface for fetching `auth/token/lookup-self`. The default
/// implementation in this crate uses `vaultrs`. Tests can substitute an
/// in-memory implementation by providing a [`VaultLookup`] directly.
#[async_trait::async_trait]
pub trait VaultLookup: Send + Sync {
    async fn lookup_self(&self) -> Result<VaultTokenInfo, VaultBridgeError>;
}

/// Translate a Vault token (via a [`VaultLookup`] handle that has the
/// token already configured) into a TrustForge `ActorIdentity`.
///
/// The actor URI is keyed by the Vault token *accessor*, not the secret
/// id, so the actor URI never contains a credential.
pub async fn vault_token_to_actor<L>(
    lookup: &L,
    cluster: &str,
) -> Result<(ActorIdentity, VaultTokenInfo), VaultBridgeError>
where
    L: VaultLookup + ?Sized,
{
    let info = lookup.lookup_self().await?;
    if info.accessor.is_empty() {
        return Err(VaultBridgeError::Rejected(
            "vault returned empty accessor".into(),
        ));
    }
    let actor_id = format!(
        "tf:actor:service:vault.{}/{}/{}",
        sanitise_segment(cluster),
        info.namespace
            .as_deref()
            .map(sanitise_segment)
            .unwrap_or_else(|| "root".into()),
        info.accessor
    );
    let identity = ActorIdentity {
        identity_version: ActorIdentity_IdentityVersion::V1,
        actor_id,
        actor_type: ActorType::Service,
        instance_id: None,
        public_keys: Vec::new(),
        trust_levels: vec![TrustLevel::T3],
        authority_roots: vec![AuthorityRoot {
            kind: AuthorityRoot_Kind::Organization,
            id: format!("vault-cluster:{cluster}"),
        }],
        attestations: None,
        valid_from: now_iso8601(),
        valid_until: None,
        revocation_ref: None,
        signature: None,
    };
    Ok((identity, info))
}

/// Translate a Vault secret path into a TrustForge `Capability`. The
/// capability name is `vault.kv.read` and the constraint pins the
/// target to `<mount>/<path>`. Risk class is `R2` (sensitive read).
pub fn vault_secret_path_to_capability(mount: &str, path: &str) -> Capability {
    let mount = mount.trim_matches('/');
    let path = path.trim_matches('/');
    let target = if path.is_empty() {
        format!("{mount}/")
    } else {
        format!("{mount}/{path}")
    };
    Capability {
        name: "vault.kv.read".into(),
        risk: RiskClass::R2,
        proof_required: None,
        approval: None,
        constraints: Some(vec![Constraint::Target {
            patterns: vec![target],
        }]),
        single_use: None,
        delegable: None,
        revocable: None,
        offline_valid: None,
        expires_at: None,
    }
}

/// Translate a list of Vault policies into TrustForge capabilities. The
/// mapping is conservative: each Vault policy name maps to a single
/// capability `vault.policy.<name>` so the daemon can later expand it
/// using the policy document. Special policies are handled directly:
///   * `root` → `vault.*` at risk R5.
///   * `default` → `vault.token.*` at risk R1.
pub fn vault_policies_to_capabilities(policies: &[String]) -> Vec<Capability> {
    let mut caps = Vec::with_capacity(policies.len());
    for p in policies {
        match p.as_str() {
            "root" => caps.push(Capability {
                name: "vault.*".into(),
                risk: RiskClass::R5,
                proof_required: None,
                approval: None,
                constraints: None,
                single_use: None,
                delegable: None,
                revocable: None,
                offline_valid: None,
                expires_at: None,
            }),
            "default" => caps.push(Capability {
                name: "vault.token.*".into(),
                risk: RiskClass::R1,
                proof_required: None,
                approval: None,
                constraints: None,
                single_use: None,
                delegable: None,
                revocable: None,
                offline_valid: None,
                expires_at: None,
            }),
            other => caps.push(Capability {
                name: format!("vault.policy.{}", sanitise_action_segment(other)),
                risk: RiskClass::R3,
                proof_required: None,
                approval: None,
                constraints: None,
                single_use: None,
                delegable: None,
                revocable: None,
                offline_valid: None,
                expires_at: None,
            }),
        }
    }
    caps
}

/// Real `vaultrs` adapter. Wrap a `vaultrs::client::VaultClient` once
/// it has been configured with a token.
pub struct VaultrsLookup {
    client: vaultrs::client::VaultClient,
}

impl VaultrsLookup {
    pub fn new(client: vaultrs::client::VaultClient) -> Self {
        VaultrsLookup { client }
    }
}

#[async_trait::async_trait]
impl VaultLookup for VaultrsLookup {
    async fn lookup_self(&self) -> Result<VaultTokenInfo, VaultBridgeError> {
        // `vaultrs::token::lookup_self` returns `LookupTokenResponse`
        // whose fields we project into our shape.
        let resp = vaultrs::token::lookup_self(&self.client)
            .await
            .map_err(|e| VaultBridgeError::Rejected(format!("lookup-self: {e}")))?;
        Ok(VaultTokenInfo {
            accessor: resp.accessor,
            display_name: resp.display_name,
            entity_id: if resp.entity_id.is_empty() {
                None
            } else {
                Some(resp.entity_id)
            },
            policies: resp.policies,
            ttl: resp.ttl,
            renewable: resp.renewable,
            orphan: resp.orphan,
            path: resp.path,
            namespace: None,
        })
    }
}

fn sanitise_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitise_action_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    iso8601_from_secs(secs)
}

fn iso8601_from_secs(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let hour = (time / 3600) as u32;
    let minute = ((time % 3600) / 60) as u32;
    let second = (time % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year as i32, m, d, hour, minute, second
    )
}

pub struct VaultBridge {
    pub bridge_id: String,
    pub trust_domain: String,
}

impl VaultBridge {
    pub fn new(bridge_id: impl Into<String>, cluster: impl Into<String>) -> Self {
        VaultBridge {
            bridge_id: bridge_id.into(),
            trust_domain: format!("vault.{}", cluster.into()),
        }
    }
}

impl Bridge for VaultBridge {
    fn bridge_id(&self) -> &str {
        &self.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Oauth
    }
    fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_path_to_capability_pins_target() {
        let cap = vault_secret_path_to_capability("kv/data", "team/secret/db-password");
        assert_eq!(cap.name, "vault.kv.read");
        assert_eq!(cap.risk, RiskClass::R2);
        let constraints = cap.constraints.unwrap();
        match &constraints[0] {
            Constraint::Target { patterns } => {
                assert_eq!(
                    patterns,
                    &vec!["kv/data/team/secret/db-password".to_string()]
                );
            }
            _ => panic!("expected target constraint"),
        }
    }

    #[test]
    fn secret_path_normalises_slashes() {
        let cap = vault_secret_path_to_capability("/secret/", "/foo/bar/");
        match cap.constraints.unwrap()[0].clone() {
            Constraint::Target { patterns } => {
                assert_eq!(patterns[0], "secret/foo/bar");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn root_policy_translates_to_wildcard() {
        let caps = vault_policies_to_capabilities(&vec!["root".into()]);
        assert_eq!(caps[0].name, "vault.*");
        assert_eq!(caps[0].risk, RiskClass::R5);
    }

    #[test]
    fn default_policy_translates_to_token_wildcard() {
        let caps = vault_policies_to_capabilities(&vec!["default".into()]);
        assert_eq!(caps[0].name, "vault.token.*");
        assert_eq!(caps[0].risk, RiskClass::R1);
    }

    #[test]
    fn custom_policy_translates_to_named_capability() {
        let caps = vault_policies_to_capabilities(&vec!["DBOps".into()]);
        assert_eq!(caps[0].name, "vault.policy.dbops");
        assert_eq!(caps[0].risk, RiskClass::R3);
    }

    #[test]
    fn sanitise_segment_replaces_specials() {
        assert_eq!(sanitise_segment("foo/bar"), "foo_bar");
        assert_eq!(sanitise_segment("foo.example.com"), "foo.example.com");
        assert_eq!(sanitise_segment("foo bar"), "foo_bar");
    }

    /// In-memory test double for the trait — used by the integration
    /// tests file as well.
    pub(crate) struct StubLookup(pub VaultTokenInfo);

    #[async_trait::async_trait]
    impl VaultLookup for StubLookup {
        async fn lookup_self(&self) -> Result<VaultTokenInfo, VaultBridgeError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn token_to_actor_uses_accessor_in_uri() {
        let info = VaultTokenInfo {
            accessor: "abc-123".into(),
            display_name: "service-x".into(),
            entity_id: Some("entity-1".into()),
            policies: vec!["default".into()],
            ttl: 3600,
            renewable: true,
            orphan: false,
            path: "auth/token/create".into(),
            namespace: Some("team-x".into()),
        };
        let lookup = StubLookup(info);
        let (actor, _info) = vault_token_to_actor(&lookup, "prod-1").await.unwrap();
        assert_eq!(
            actor.actor_id,
            "tf:actor:service:vault.prod-1/team-x/abc-123"
        );
        assert_eq!(actor.actor_type, ActorType::Service);
        assert_eq!(actor.authority_roots[0].id, "vault-cluster:prod-1");
    }
}
