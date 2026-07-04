//! TrustForge bridge for Azure AD / Entra ID.
//!
//! Three primary entry points:
//!
//! 1. [`verify_azure_jwt`] — verify an Azure-issued JWT (managed
//!    identity, app registration, user) against the tenant's discovery
//!    JWKS at
//!    `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`.
//!
//! 2. [`managed_identity_to_actor`] — translate verified Azure claims
//!    into a TrustForge `ActorIdentity`, using the `oid` (object id) as
//!    the stable principal identifier.
//!
//! 3. [`azure_role_assignment_to_capabilities`] — map common Azure RBAC
//!    role names (built-in roles such as "Storage Blob Data Reader") to
//!    TrustForge capabilities.
//!
//! Note on dependencies: Azure JWT *verification* only requires
//! `jsonwebtoken` + `reqwest`. The `azure_identity` crate is for
//! *acquiring* outbound tokens (DefaultAzureCredential, federated
//! workload identity) — not what this bridge does. Adding it would pull
//! in the entire azure_core stack with no functional benefit, so we
//! omit it. Future revisions that need outbound token issuance (so the
//! daemon can call back to Azure on the user's behalf) should add it
//! behind a feature flag.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use tf_types::jws::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use tf_types::bridges::{Bridge, BridgeKind};
use tf_types::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    Capability, RiskClass, TrustLevel,
};

#[derive(Debug, Error)]
pub enum AzureBridgeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
    #[error("token rejected: {0}")]
    Rejected(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Build the Azure tenant JWKS URL for a tenant ID. Pass `"common"` to
/// get the multi-tenant endpoint, or a tenant GUID/domain for a
/// single-tenant app.
pub fn azure_jwks_url(tenant: &str) -> String {
    format!(
        "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
        tenant
    )
}

/// Build the canonical Azure issuer string for a tenant.
pub fn azure_issuer(tenant: &str) -> String {
    format!("https://login.microsoftonline.com/{}/v2.0", tenant)
}

/// Verified Azure identity claims, normalised. `oid` is the stable
/// object ID, `tid` is the tenant ID, `appid` is the registered app
/// (when this is an app-only token).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AzureIdentity {
    pub iss: String,
    pub sub: String,
    pub oid: Option<String>,
    pub tid: Option<String>,
    pub aud: String,
    pub appid: Option<String>,
    pub upn: Option<String>,
    pub email: Option<String>,
    pub roles: Vec<String>,
    /// `idtyp` claim — `app` for managed-identity / app-only tokens,
    /// otherwise unset.
    pub idtyp: Option<String>,
    pub exp: u64,
    pub iat: u64,
    pub raw: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    aud: serde_json::Value,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    roles: Option<Vec<String>>,
    #[serde(default)]
    idtyp: Option<String>,
    exp: u64,
    iat: u64,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct AzureJwks {
    keys: Vec<AzureJwk>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
struct AzureJwk {
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    #[serde(rename = "use")]
    use_: Option<String>,
}

#[derive(Debug)]
struct CachedJwks {
    fetched_at: std::time::Instant,
    keys: Vec<AzureJwk>,
}

/// Async verifier for Azure JWTs. Caches JWKS in memory for
/// `cache_ttl_seconds`.
pub struct AzureJwtVerifier {
    jwks_url: String,
    issuer: String,
    audience: Vec<String>,
    cache_ttl_seconds: u64,
    cached: Mutex<Option<CachedJwks>>,
    http: reqwest::Client,
}

impl AzureJwtVerifier {
    /// Construct a verifier pointed at the public Azure tenant.
    pub fn for_tenant(tenant: impl AsRef<str>, audience: Vec<String>) -> Self {
        let tenant = tenant.as_ref();
        Self::new(azure_jwks_url(tenant), azure_issuer(tenant), audience)
    }

    pub fn new(
        jwks_url: impl Into<String>,
        issuer: impl Into<String>,
        audience: Vec<String>,
    ) -> Self {
        AzureJwtVerifier {
            jwks_url: jwks_url.into(),
            issuer: issuer.into(),
            audience,
            cache_ttl_seconds: 600,
            cached: Mutex::new(None),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn with_cache_ttl(mut self, secs: u64) -> Self {
        self.cache_ttl_seconds = secs;
        self
    }

    async fn fetch_keys(&self) -> Result<Vec<AzureJwk>, AzureBridgeError> {
        {
            let cache = self.cached.lock().expect("cache poisoned");
            if let Some(c) = cache.as_ref() {
                if c.fetched_at.elapsed().as_secs() < self.cache_ttl_seconds {
                    return Ok(c.keys.clone());
                }
            }
        }
        let resp = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| AzureBridgeError::Jwks(format!("get: {e}")))?;
        if !resp.status().is_success() {
            return Err(AzureBridgeError::Jwks(format!(
                "JWKS endpoint returned {}",
                resp.status()
            )));
        }
        let jwks: AzureJwks = resp
            .json()
            .await
            .map_err(|e| AzureBridgeError::Jwks(format!("parse: {e}")))?;
        let mut cache = self.cached.lock().expect("cache poisoned");
        *cache = Some(CachedJwks {
            fetched_at: std::time::Instant::now(),
            keys: jwks.keys.clone(),
        });
        Ok(jwks.keys)
    }

    pub async fn verify(&self, jwt: &str) -> Result<AzureIdentity, AzureBridgeError> {
        if jwt.is_empty() {
            return Err(AzureBridgeError::InvalidInput("empty token".into()));
        }
        let header = decode_header(jwt)
            .map_err(|e| AzureBridgeError::Rejected(format!("malformed: {e}")))?;
        if header.algorithm().ok() != Some(Algorithm::RS256) {
            return Err(AzureBridgeError::Rejected(format!(
                "Azure tokens require RS256, got {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AzureBridgeError::Rejected("missing kid".into()))?;
        let keys = self.fetch_keys().await?;
        let jwk = keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| AzureBridgeError::Rejected(format!("no JWK with kid {kid}")))?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| AzureBridgeError::Internal(format!("bad RSA components: {e}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        if !self.audience.is_empty() {
            validation.set_audience(&self.audience);
        }
        let data = decode::<RawClaims>(jwt, &key, &validation)
            .map_err(|e| AzureBridgeError::Rejected(format!("verify failed: {e}")))?;
        let claims = data.claims;
        let aud = match &claims.aud {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) if !arr.is_empty() => {
                arr[0].as_str().map(str::to_string).unwrap_or_default()
            }
            _ => String::new(),
        };
        let raw = serde_json::to_value(&claims).unwrap_or(serde_json::Value::Null);
        Ok(AzureIdentity {
            iss: claims.iss,
            sub: claims.sub,
            oid: claims.oid,
            tid: claims.tid,
            aud,
            appid: claims.appid,
            upn: claims.upn,
            email: claims.email,
            roles: claims.roles.unwrap_or_default(),
            idtyp: claims.idtyp,
            exp: claims.exp,
            iat: claims.iat,
            raw,
        })
    }
}

/// Convenience wrapper around [`AzureJwtVerifier::verify`].
pub async fn verify_azure_jwt(
    verifier: &AzureJwtVerifier,
    jwt: &str,
) -> Result<AzureIdentity, AzureBridgeError> {
    verifier.verify(jwt).await
}

/// Translate verified Azure claims into a TrustForge actor.
///
/// Actor type is `Service` when the token is app-only (`idtyp=app` or
/// `appid` set without `upn`), otherwise `Human`.
///
/// Actor URI scheme:
///
/// ```text
/// tf:actor:<type>:login.microsoftonline.com/<tenant-id>/<oid>
/// ```
pub fn managed_identity_to_actor(
    claims: &AzureIdentity,
) -> Result<ActorIdentity, AzureBridgeError> {
    let tid = claims
        .tid
        .clone()
        .ok_or_else(|| AzureBridgeError::InvalidInput("missing tid claim".into()))?;
    let oid = claims
        .oid
        .clone()
        .or_else(|| Some(claims.sub.clone()))
        .ok_or_else(|| AzureBridgeError::InvalidInput("missing oid/sub".into()))?;
    let is_app =
        claims.idtyp.as_deref() == Some("app") || (claims.appid.is_some() && claims.upn.is_none());
    let (actor_type, type_segment) = if is_app {
        (ActorType::Service, "service")
    } else {
        (ActorType::Human, "human")
    };
    let actor_id = format!(
        "tf:actor:{}:login.microsoftonline.com/{}/{}",
        type_segment, tid, oid
    );
    Ok(ActorIdentity {
        identity_version: ActorIdentity_IdentityVersion::V1,
        actor_id,
        actor_type,
        instance_id: None,
        public_keys: Vec::new(),
        trust_levels: vec![TrustLevel::T3],
        authority_roots: vec![AuthorityRoot {
            kind: AuthorityRoot_Kind::Organization,
            id: format!("azure-tenant:{}", tid),
        }],
        attestations: None,
        valid_from: now_iso8601(),
        valid_until: Some(iso8601_from_secs(claims.exp as i64)),
        revocation_ref: None,
        signature: None,
    })
}

/// Translate an Azure RBAC built-in role name into TrustForge
/// capabilities. Unknown roles produce a single wildcard capability so
/// the policy engine can decide what to do (typically refuse).
pub fn azure_role_assignment_to_capabilities(role: &str) -> Vec<Capability> {
    let mapping = role_to_actions(role);
    mapping
        .into_iter()
        .map(|(name, risk)| Capability {
            name: name.to_string(),
            risk,
            proof_required: None,
            approval: None,
            constraints: None,
            single_use: None,
            delegable: None,
            revocable: None,
            offline_valid: None,
            expires_at: None,
        })
        .collect()
}

fn role_to_actions(role: &str) -> Vec<(&'static str, RiskClass)> {
    match role {
        "Reader" => vec![("azure.*.read", RiskClass::R1)],
        "Contributor" => vec![("azure.*", RiskClass::R4)],
        "Owner" => vec![("azure.*", RiskClass::R5)],
        "User Access Administrator" => vec![("azure.authorization.*", RiskClass::R5)],
        "Storage Blob Data Reader" => vec![
            ("azure.storage.read_blob", RiskClass::R1),
            ("azure.storage.list_blobs", RiskClass::R1),
        ],
        "Storage Blob Data Contributor" => vec![
            ("azure.storage.read_blob", RiskClass::R1),
            ("azure.storage.list_blobs", RiskClass::R1),
            ("azure.storage.write_blob", RiskClass::R3),
            ("azure.storage.delete_blob", RiskClass::R3),
        ],
        "Storage Blob Data Owner" => vec![("azure.storage.*", RiskClass::R3)],
        "Key Vault Secrets User" => vec![("azure.keyvault.get_secret", RiskClass::R2)],
        "Key Vault Secrets Officer" => vec![
            ("azure.keyvault.get_secret", RiskClass::R2),
            ("azure.keyvault.set_secret", RiskClass::R3),
            ("azure.keyvault.delete_secret", RiskClass::R3),
        ],
        "Key Vault Administrator" => vec![("azure.keyvault.*", RiskClass::R5)],
        "Virtual Machine Contributor" => vec![("azure.compute.virtualmachines.*", RiskClass::R4)],
        "Network Contributor" => vec![("azure.network.*", RiskClass::R4)],
        "Monitoring Reader" => vec![("azure.monitor.read", RiskClass::R1)],
        "Log Analytics Reader" => vec![("azure.loganalytics.read", RiskClass::R1)],
        _ => vec![("azure.unknown_role.*", RiskClass::R3)],
    }
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

pub struct AzureBridge {
    pub bridge_id: String,
    pub trust_domain: String,
}

impl AzureBridge {
    pub fn new(bridge_id: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        AzureBridge {
            bridge_id: bridge_id.into(),
            trust_domain: format!("login.microsoftonline.com/{}", tenant_id.into()),
        }
    }
}

impl Bridge for AzureBridge {
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
    fn jwks_url_built_for_tenant() {
        assert_eq!(
            azure_jwks_url("contoso.onmicrosoft.com"),
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/discovery/v2.0/keys"
        );
    }

    #[test]
    fn issuer_built_for_tenant() {
        assert_eq!(
            azure_issuer("00000000-0000-0000-0000-000000000000"),
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
        );
    }

    #[test]
    fn managed_identity_app_token_becomes_service_actor() {
        let ai = AzureIdentity {
            iss: "https://login.microsoftonline.com/tid/v2.0".into(),
            sub: "subject-1".into(),
            oid: Some("oid-app-1".into()),
            tid: Some("tid-1".into()),
            aud: "api://x".into(),
            appid: Some("app-1".into()),
            upn: None,
            email: None,
            roles: Vec::new(),
            idtyp: Some("app".into()),
            exp: 0,
            iat: 0,
            raw: serde_json::Value::Null,
        };
        let actor = managed_identity_to_actor(&ai).unwrap();
        assert_eq!(
            actor.actor_id,
            "tf:actor:service:login.microsoftonline.com/tid-1/oid-app-1"
        );
        assert_eq!(actor.actor_type, ActorType::Service);
    }

    #[test]
    fn user_token_becomes_human_actor() {
        let ai = AzureIdentity {
            iss: "https://login.microsoftonline.com/tid/v2.0".into(),
            sub: "subject-1".into(),
            oid: Some("oid-user-1".into()),
            tid: Some("tid-1".into()),
            aud: "api://x".into(),
            appid: Some("app-1".into()),
            upn: Some("alice@contoso.com".into()),
            email: Some("alice@contoso.com".into()),
            roles: Vec::new(),
            idtyp: None,
            exp: 0,
            iat: 0,
            raw: serde_json::Value::Null,
        };
        let actor = managed_identity_to_actor(&ai).unwrap();
        assert_eq!(actor.actor_type, ActorType::Human);
        assert!(actor.actor_id.starts_with("tf:actor:human:"));
    }

    #[test]
    fn role_translation_known_roles() {
        let owner = azure_role_assignment_to_capabilities("Owner");
        assert_eq!(owner[0].risk, RiskClass::R5);
        let reader = azure_role_assignment_to_capabilities("Reader");
        assert_eq!(reader[0].risk, RiskClass::R1);
        let blob_user = azure_role_assignment_to_capabilities("Storage Blob Data Reader");
        assert_eq!(blob_user.len(), 2);
    }

    #[test]
    fn role_translation_unknown_falls_back() {
        let unk = azure_role_assignment_to_capabilities("Some Custom Role");
        assert_eq!(unk[0].name, "azure.unknown_role.*");
        assert_eq!(unk[0].risk, RiskClass::R3);
    }
}
