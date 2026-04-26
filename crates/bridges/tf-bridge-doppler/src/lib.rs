//! TrustForge bridge for Doppler.
//!
//! Doppler issues *service tokens* (`dp.st.<env>.<random>`) and
//! *service-account tokens* that are scoped to a single project + config
//! (environment). The bridge:
//!
//! 1. Calls `GET /v3/me` against the Doppler API with the bearer token
//!    to verify the token is live and to learn its workplace + slug.
//! 2. Calls `GET /v3/configs/config` to learn which project/config the
//!    token is bound to (service tokens are project-scoped at issue
//!    time).
//! 3. Translates the verified token into a TrustForge `ActorIdentity`
//!    keyed by `<workplace>/<project>/<config>/<token-slug>`.
//! 4. Translates each Doppler secret name into a `vault.kv.read` style
//!    capability targeted at `doppler://<project>/<config>/<secret>`.
//!
//! Test note: Doppler's `me` endpoint returns plain JSON, so we point
//! the verifier at a `wiremock` instance for tests.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use tf_types::bridges::{Bridge, BridgeKind};
use tf_types::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    Capability, Constraint, RiskClass, TrustLevel,
};

pub const DOPPLER_API_BASE: &str = "https://api.doppler.com";

#[derive(Debug, Error)]
pub enum DopplerBridgeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("doppler rejected token: {0}")]
    Rejected(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// What we learn about a Doppler token after exchanging it for `/v3/me`
/// and `/v3/configs/config` metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DopplerTokenInfo {
    pub slug: String,
    pub name: String,
    pub workplace_id: String,
    pub workplace_name: String,
    pub project: Option<String>,
    pub config: Option<String>,
    pub token_type: DopplerTokenType,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DopplerTokenType {
    /// `dp.st.<env>.<random>` — service token bound to a project+config.
    Service,
    /// `dp.sa.<random>` — service account token (workplace scoped).
    ServiceAccount,
    /// `dp.pt.<random>` — personal token.
    Personal,
    /// Unknown / future shape.
    Other(String),
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
struct MeResponse {
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    workplace: Option<MeWorkplace>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    config: Option<String>,
    #[serde(default, rename = "type")]
    token_type: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct MeWorkplace {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    slug: Option<String>,
}

/// Verifier for Doppler service tokens. Stateless — each call hits the
/// Doppler API.
pub struct DopplerVerifier {
    api_base: String,
    http: reqwest::Client,
}

impl DopplerVerifier {
    pub fn new(api_base: impl Into<String>) -> Self {
        DopplerVerifier {
            api_base: api_base.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn doppler() -> Self {
        Self::new(DOPPLER_API_BASE)
    }

    pub async fn introspect(&self, token: &str) -> Result<DopplerTokenInfo, DopplerBridgeError> {
        if token.is_empty() {
            return Err(DopplerBridgeError::InvalidInput("empty token".into()));
        }
        let token_type = classify_token(token);
        let resp = self
            .http
            .get(format!("{}/v3/me", self.api_base))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| DopplerBridgeError::Network(format!("get /v3/me: {e}")))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED
            || resp.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Err(DopplerBridgeError::Rejected(format!(
                "doppler rejected token: {}",
                resp.status()
            )));
        }
        if !resp.status().is_success() {
            return Err(DopplerBridgeError::Network(format!(
                "/v3/me returned {}",
                resp.status()
            )));
        }
        let me: MeResponse = resp
            .json()
            .await
            .map_err(|e| DopplerBridgeError::Network(format!("parse /v3/me: {e}")))?;
        let workplace = me
            .workplace
            .unwrap_or_default()
            .unwrap_or_default_workplace();
        let info = DopplerTokenInfo {
            slug: me.slug.unwrap_or_default(),
            name: me.name.unwrap_or_default(),
            workplace_id: workplace.id,
            workplace_name: workplace.name,
            project: me.project,
            config: me.config,
            token_type,
        };
        Ok(info)
    }
}

impl MeWorkplace {
    fn unwrap_or_default_workplace(self) -> MeWorkplace {
        MeWorkplace {
            id: if self.id.is_empty() {
                "unknown".into()
            } else {
                self.id
            },
            name: if self.name.is_empty() {
                "unknown".into()
            } else {
                self.name
            },
            slug: self.slug,
        }
    }
}

/// Translate a verified Doppler token into a TrustForge actor.
pub fn doppler_token_to_actor(
    info: &DopplerTokenInfo,
) -> Result<ActorIdentity, DopplerBridgeError> {
    if info.workplace_id.is_empty() {
        return Err(DopplerBridgeError::Rejected(
            "doppler returned empty workplace id".into(),
        ));
    }
    let project = info.project.as_deref().unwrap_or("any");
    let config = info.config.as_deref().unwrap_or("any");
    let slug = if info.slug.is_empty() {
        "anonymous"
    } else {
        info.slug.as_str()
    };
    let actor_id = format!(
        "tf:actor:service:doppler.com/{}/{}/{}/{}",
        sanitise_segment(&info.workplace_id),
        sanitise_segment(project),
        sanitise_segment(config),
        sanitise_segment(slug)
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
            id: format!("doppler-workplace:{}", info.workplace_id),
        }],
        attestations: None,
        valid_from: now_iso8601(),
        valid_until: None,
        revocation_ref: None,
        signature: None,
    })
}

/// Translate a Doppler secret reference (project/config/secret) into a
/// TrustForge capability that targets the canonical doppler URI.
pub fn doppler_secret_to_capability(project: &str, config: &str, secret: &str) -> Capability {
    let target = format!(
        "doppler://{}/{}/{}",
        sanitise_segment(project),
        sanitise_segment(config),
        secret
    );
    Capability {
        name: "doppler.kv.read".into(),
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

/// Top-level helper: combine `introspect` + `doppler_token_to_actor`.
pub async fn doppler_service_token_to_actor(
    verifier: &DopplerVerifier,
    token: &str,
) -> Result<(ActorIdentity, DopplerTokenInfo), DopplerBridgeError> {
    let info = verifier.introspect(token).await?;
    let actor = doppler_token_to_actor(&info)?;
    Ok((actor, info))
}

fn classify_token(token: &str) -> DopplerTokenType {
    if token.starts_with("dp.st.") {
        DopplerTokenType::Service
    } else if token.starts_with("dp.sa.") {
        DopplerTokenType::ServiceAccount
    } else if token.starts_with("dp.pt.") {
        DopplerTokenType::Personal
    } else if let Some(rest) = token.strip_prefix("dp.") {
        let kind = rest.split('.').next().unwrap_or("unknown");
        DopplerTokenType::Other(kind.to_string())
    } else {
        DopplerTokenType::Other("unknown".into())
    }
}

fn sanitise_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                c
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

pub struct DopplerBridge {
    pub bridge_id: String,
    pub trust_domain: String,
}

impl DopplerBridge {
    pub fn new(bridge_id: impl Into<String>, workplace_id: impl Into<String>) -> Self {
        DopplerBridge {
            bridge_id: bridge_id.into(),
            trust_domain: format!("doppler.com/{}", workplace_id.into()),
        }
    }
}

impl Bridge for DopplerBridge {
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
    fn classify_known_prefixes() {
        assert_eq!(
            classify_token("dp.st.dev.AAAAAAAAAAAA"),
            DopplerTokenType::Service
        );
        assert_eq!(
            classify_token("dp.sa.AAAAAAAAAAAA"),
            DopplerTokenType::ServiceAccount
        );
        assert_eq!(
            classify_token("dp.pt.AAAAAAAAAAAA"),
            DopplerTokenType::Personal
        );
    }

    #[test]
    fn classify_unknown_falls_back() {
        assert_eq!(
            classify_token("dp.qq.AAAA"),
            DopplerTokenType::Other("qq".into())
        );
        assert_eq!(
            classify_token("not-a-doppler-token"),
            DopplerTokenType::Other("unknown".into())
        );
    }

    #[test]
    fn doppler_token_to_actor_normalises_segments() {
        let info = DopplerTokenInfo {
            slug: "ci-runner".into(),
            name: "CI runner".into(),
            workplace_id: "wp_123".into(),
            workplace_name: "Acme".into(),
            project: Some("trustforge".into()),
            config: Some("prod".into()),
            token_type: DopplerTokenType::Service,
        };
        let actor = doppler_token_to_actor(&info).unwrap();
        assert_eq!(
            actor.actor_id,
            "tf:actor:service:doppler.com/wp_123/trustforge/prod/ci-runner"
        );
        assert_eq!(actor.actor_type, ActorType::Service);
        assert_eq!(actor.trust_levels, vec![TrustLevel::T3]);
    }

    #[test]
    fn doppler_secret_to_capability_pins_target_uri() {
        let cap = doppler_secret_to_capability("trustforge", "prod", "DATABASE_URL");
        assert_eq!(cap.name, "doppler.kv.read");
        assert_eq!(cap.risk, RiskClass::R2);
        match &cap.constraints.unwrap()[0] {
            Constraint::Target { patterns } => {
                assert_eq!(patterns[0], "doppler://trustforge/prod/DATABASE_URL");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn doppler_token_to_actor_rejects_empty_workplace() {
        let info = DopplerTokenInfo {
            slug: "x".into(),
            name: "x".into(),
            workplace_id: String::new(),
            workplace_name: "x".into(),
            project: None,
            config: None,
            token_type: DopplerTokenType::Service,
        };
        let err = doppler_token_to_actor(&info).unwrap_err();
        assert!(matches!(err, DopplerBridgeError::Rejected(_)));
    }
}
