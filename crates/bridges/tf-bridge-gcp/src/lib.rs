//! TrustForge bridge for GCP IAM.
//!
//! Three primary entry points:
//!
//! 1. [`verify_gcp_id_token`] — verify a Google-issued OIDC ID token by
//!    fetching the JWKS at
//!    `https://www.googleapis.com/oauth2/v3/certs` (override for tests)
//!    and checking the RS256 signature, issuer, and audience.
//!
//! 2. [`service_account_to_actor`] — translate a verified GCP service
//!    account principal into a TrustForge `ActorIdentity`.
//!
//! 3. [`gcp_iam_role_to_capabilities`] — map common predefined GCP roles
//!    (`roles/storage.objectViewer`, `roles/iam.serviceAccountUser`,
//!    etc.) into TrustForge capabilities.

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

/// Default Google OIDC issuer.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
/// Default Google JWKS endpoint.
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Debug, Error)]
pub enum GcpBridgeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
    #[error("token rejected: {0}")]
    Rejected(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Verified Google identity claims, normalised. The `sub` is the stable
/// Google numeric user-ID; `email` is the claimed email address (only
/// trusted when `email_verified` is true).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GcpIdentity {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub hd: Option<String>,
    pub azp: Option<String>,
    pub exp: u64,
    pub iat: u64,
    /// The original raw claims for callers that need them.
    pub raw: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    aud: serde_json::Value,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    hd: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    exp: u64,
    iat: u64,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
struct GoogleJwk {
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

/// Information about a GCP service account that we project into a
/// TrustForge actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GcpServiceAccountInfo {
    /// Service-account email — `<sa>@<project>.iam.gserviceaccount.com`
    /// or `<num>-compute@developer.gserviceaccount.com`.
    pub email: String,
    /// GCP project ID. Inferred from the email if absent.
    pub project_id: Option<String>,
    /// Optional unique ID (Google numeric SA ID).
    pub unique_id: Option<String>,
}

/// Async verifier for Google ID tokens. Caches JWKS in memory for
/// `cache_ttl_seconds` to avoid hammering the discovery endpoint.
pub struct GcpIdTokenVerifier {
    jwks_url: String,
    issuer: String,
    audience: Vec<String>,
    cache_ttl_seconds: u64,
    cached: Mutex<Option<CachedJwks>>,
    http: reqwest::Client,
}

#[derive(Debug)]
struct CachedJwks {
    fetched_at: std::time::Instant,
    keys: Vec<GoogleJwk>,
}

impl GcpIdTokenVerifier {
    /// Construct a verifier for the canonical Google issuer.
    pub fn google(audience: Vec<String>) -> Self {
        Self::new(GOOGLE_JWKS_URL, GOOGLE_ISSUER, audience)
    }

    pub fn new(
        jwks_url: impl Into<String>,
        issuer: impl Into<String>,
        audience: Vec<String>,
    ) -> Self {
        GcpIdTokenVerifier {
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

    async fn fetch_keys(&self) -> Result<Vec<GoogleJwk>, GcpBridgeError> {
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
            .map_err(|e| GcpBridgeError::Jwks(format!("get: {e}")))?;
        if !resp.status().is_success() {
            return Err(GcpBridgeError::Jwks(format!(
                "JWKS endpoint returned {}",
                resp.status()
            )));
        }
        let jwks: GoogleJwks = resp
            .json()
            .await
            .map_err(|e| GcpBridgeError::Jwks(format!("parse: {e}")))?;
        let mut cache = self.cached.lock().expect("cache poisoned");
        *cache = Some(CachedJwks {
            fetched_at: std::time::Instant::now(),
            keys: jwks.keys.clone(),
        });
        Ok(jwks.keys)
    }
}

/// Verify a GCP ID token (Google OIDC) using the canonical Google JWKS.
/// Convenience wrapper around [`GcpIdTokenVerifier::verify`].
pub async fn verify_gcp_id_token(
    verifier: &GcpIdTokenVerifier,
    jwt: &str,
) -> Result<GcpIdentity, GcpBridgeError> {
    verifier.verify(jwt).await
}

impl GcpIdTokenVerifier {
    pub async fn verify(&self, jwt: &str) -> Result<GcpIdentity, GcpBridgeError> {
        if jwt.is_empty() {
            return Err(GcpBridgeError::InvalidInput("empty token".into()));
        }
        let header =
            decode_header(jwt).map_err(|e| GcpBridgeError::Rejected(format!("malformed: {e}")))?;
        if header.algorithm().ok() != Some(Algorithm::RS256) {
            return Err(GcpBridgeError::Rejected(format!(
                "Google ID tokens require RS256, got {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| GcpBridgeError::Rejected("missing kid".into()))?;
        let keys = self.fetch_keys().await?;
        let jwk = keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| GcpBridgeError::Rejected(format!("no JWK with kid {kid}")))?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| GcpBridgeError::Internal(format!("bad RSA components: {e}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        if !self.audience.is_empty() {
            validation.set_audience(&self.audience);
        }
        let data = decode::<RawClaims>(jwt, &key, &validation)
            .map_err(|e| GcpBridgeError::Rejected(format!("verify failed: {e}")))?;
        let claims = data.claims;
        let aud = match &claims.aud {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) if !arr.is_empty() => {
                arr[0].as_str().map(str::to_string).unwrap_or_default()
            }
            _ => String::new(),
        };
        let email_verified = match &claims.email_verified {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => s == "true",
            _ => false,
        };
        let raw = serde_json::to_value(&claims).unwrap_or(serde_json::Value::Null);
        Ok(GcpIdentity {
            iss: claims.iss,
            sub: claims.sub,
            aud,
            email: claims.email,
            email_verified,
            hd: claims.hd,
            azp: claims.azp,
            exp: claims.exp,
            iat: claims.iat,
            raw,
        })
    }
}

/// Translate a GCP service account principal into a TrustForge actor.
pub fn service_account_to_actor(
    sa: &GcpServiceAccountInfo,
) -> Result<ActorIdentity, GcpBridgeError> {
    if sa.email.is_empty() {
        return Err(GcpBridgeError::InvalidInput("empty SA email".into()));
    }
    let project = sa
        .project_id
        .clone()
        .or_else(|| infer_project_from_email(&sa.email))
        .ok_or_else(|| {
            GcpBridgeError::InvalidInput(format!("cannot infer project from SA email {}", sa.email))
        })?;
    let local = sa.email.split('@').next().unwrap_or(&sa.email).to_string();
    let actor_id = format!(
        "tf:actor:service:gcp.googleapis.com/{}/sa/{}",
        project, local
    );
    Ok(ActorIdentity {
        identity_version: ActorIdentity_IdentityVersion::V1,
        actor_id,
        actor_type: ActorType::Service,
        instance_id: None,
        public_keys: Vec::new(),
        trust_levels: vec![TrustLevel::T3],
        authority_roots: vec![AuthorityRoot {
            kind: AuthorityRoot_Kind::Organization,
            id: format!("projects/{project}"),
        }],
        attestations: None,
        valid_from: now_iso8601(),
        valid_until: None,
        revocation_ref: None,
        signature: None,
    })
}

/// Translate a GCP IAM role identifier (e.g. `roles/storage.objectViewer`)
/// into a list of TrustForge capabilities. Mappings are intentionally
/// conservative: we only emit capabilities for the well-known predefined
/// roles, and emit a single wildcard capability for unknown roles so the
/// caller can decide what to do (typically pair with a deny-by-default
/// policy).
pub fn gcp_iam_role_to_capabilities(role: &str) -> Vec<Capability> {
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
        "roles/storage.objectViewer" => vec![
            ("gcp.storage.get_object", RiskClass::R1),
            ("gcp.storage.list_objects", RiskClass::R1),
        ],
        "roles/storage.objectAdmin" => vec![
            ("gcp.storage.get_object", RiskClass::R1),
            ("gcp.storage.list_objects", RiskClass::R1),
            ("gcp.storage.create_object", RiskClass::R3),
            ("gcp.storage.delete_object", RiskClass::R3),
            ("gcp.storage.update_object", RiskClass::R3),
        ],
        "roles/storage.objectCreator" => vec![("gcp.storage.create_object", RiskClass::R3)],
        "roles/storage.admin" => vec![("gcp.storage.*", RiskClass::R3)],
        "roles/iam.serviceAccountUser" => vec![("gcp.iam.actas_service_account", RiskClass::R3)],
        "roles/iam.serviceAccountTokenCreator" => {
            vec![("gcp.iam.create_service_account_token", RiskClass::R3)]
        }
        "roles/iam.workloadIdentityUser" => vec![("gcp.iam.workload_identity", RiskClass::R3)],
        "roles/secretmanager.secretAccessor" => {
            vec![("gcp.secretmanager.access_secret", RiskClass::R2)]
        }
        "roles/secretmanager.admin" => vec![("gcp.secretmanager.*", RiskClass::R3)],
        "roles/pubsub.publisher" => vec![("gcp.pubsub.publish", RiskClass::R2)],
        "roles/pubsub.subscriber" => vec![
            ("gcp.pubsub.consume", RiskClass::R1),
            ("gcp.pubsub.ack", RiskClass::R1),
        ],
        "roles/cloudfunctions.invoker" => vec![("gcp.cloudfunctions.invoke", RiskClass::R2)],
        "roles/run.invoker" => vec![("gcp.run.invoke", RiskClass::R2)],
        "roles/owner" => vec![("gcp.*", RiskClass::R5)],
        "roles/editor" => vec![("gcp.*", RiskClass::R4)],
        "roles/viewer" => vec![("gcp.*.get", RiskClass::R1), ("gcp.*.list", RiskClass::R1)],
        _ => vec![(unknown_role_to_action_static(role), RiskClass::R3)],
    }
}

fn unknown_role_to_action_static(_role: &str) -> &'static str {
    // We can't return a borrowed string with a non-static lifetime from
    // a `&'static str`-yielding match arm. Callers receive a single
    // wildcard so the policy engine sees the role exists but the
    // bridge declines to enumerate.
    "gcp.unknown_role.*"
}

fn infer_project_from_email(email: &str) -> Option<String> {
    // foo@bar-project.iam.gserviceaccount.com
    if let Some(domain) = email.split('@').nth(1) {
        if let Some(p) = domain.strip_suffix(".iam.gserviceaccount.com") {
            return Some(p.to_string());
        }
        // numeric-compute@developer.gserviceaccount.com — no project
        // embedded; caller must pass project_id explicitly.
    }
    None
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

/// Bridge handle for registry registration.
pub struct GcpBridge {
    pub bridge_id: String,
    pub trust_domain: String,
}

impl GcpBridge {
    pub fn new(bridge_id: impl Into<String>, project_id: impl Into<String>) -> Self {
        GcpBridge {
            bridge_id: bridge_id.into(),
            trust_domain: format!("gcp.googleapis.com/{}", project_id.into()),
        }
    }
}

impl Bridge for GcpBridge {
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
    fn service_account_translation_infers_project() {
        let sa = GcpServiceAccountInfo {
            email: "code-helper@example-prod.iam.gserviceaccount.com".into(),
            project_id: None,
            unique_id: Some("123456".into()),
        };
        let actor = service_account_to_actor(&sa).unwrap();
        assert_eq!(
            actor.actor_id,
            "tf:actor:service:gcp.googleapis.com/example-prod/sa/code-helper"
        );
        assert_eq!(actor.actor_type, ActorType::Service);
    }

    #[test]
    fn unknown_role_returns_wildcard() {
        let caps = gcp_iam_role_to_capabilities("roles/some.weird.role");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "gcp.unknown_role.*");
        assert_eq!(caps[0].risk, RiskClass::R3);
    }

    #[test]
    fn storage_object_viewer_has_only_read_capabilities() {
        let caps = gcp_iam_role_to_capabilities("roles/storage.objectViewer");
        assert_eq!(caps.len(), 2);
        for cap in &caps {
            assert_eq!(cap.risk, RiskClass::R1);
        }
    }

    #[test]
    fn owner_role_is_high_risk_wildcard() {
        let caps = gcp_iam_role_to_capabilities("roles/owner");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "gcp.*");
        assert_eq!(caps[0].risk, RiskClass::R5);
    }
}
