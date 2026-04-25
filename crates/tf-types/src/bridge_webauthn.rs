//! WebAuthn bridge — Rust mirror of `tools/tf-types-ts/src/core/bridge-webauthn.ts`.
//!
//! Maps a structured WebAuthn credential to a TrustForge actor identity
//! and back. The full attestation parser/verifier lives in
//! `webauthn_attestation.rs`; this module is the thin surface the
//! BridgeRegistry hands to callers (matching the TS API), so contracts
//! that already carry a verified credential can be promoted to an
//! `ActorIdentity` without re-running attestation.

use serde::{Deserialize, Serialize};

use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    PublicKey, PublicKey_Purpose, TrustLevel,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WebAuthnCredential {
    pub credential_id: String,
    pub public_key: String,
    pub algorithm: String,
    pub rp_id: String,
    pub user_handle: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aaguid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct WebAuthnBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub rp_id: String,
    /// Optional algorithm allow-list. If set, accept rejects credentials
    /// whose algorithm field is not in the list.
    pub allowed_algorithms: Option<Vec<String>>,
}

pub struct WebAuthnBridge {
    cfg: WebAuthnBridgeConfig,
}

impl WebAuthnBridge {
    pub fn new(cfg: WebAuthnBridgeConfig) -> Self {
        WebAuthnBridge { cfg }
    }

    /// Promote a structured WebAuthn credential to a TrustForge
    /// ActorIdentity using the bridge's rp_id binding and algorithm
    /// allow-list. Mirrors TS `WebAuthnBridge.accept`.
    pub fn accept(&self, cred: &WebAuthnCredential) -> Result<ActorIdentity, BridgeError> {
        if cred.public_key.is_empty() {
            return Err(BridgeError::InvalidInput("missing public_key".into()));
        }
        if cred.rp_id.is_empty() {
            return Err(BridgeError::InvalidInput("missing rp_id".into()));
        }
        if cred.user_handle.is_empty() {
            return Err(BridgeError::InvalidInput("missing user_handle".into()));
        }
        if !self.cfg.rp_id.is_empty() && self.cfg.rp_id != cred.rp_id {
            return Err(BridgeError::Rejected(format!(
                "credential rp_id {} does not match bridge rp_id {}",
                cred.rp_id, self.cfg.rp_id
            )));
        }
        if let Some(allow) = &self.cfg.allowed_algorithms {
            if !allow.iter().any(|a| a == &cred.algorithm) {
                return Err(BridgeError::Rejected(format!(
                    "algorithm {} is not in the bridge's allow-list",
                    cred.algorithm
                )));
            }
        }
        let now = current_iso8601();
        let actor_id = format!(
            "tf:actor:human:{}/{}",
            cred.rp_id,
            slug(&cred.user_handle)
        );
        let identity = ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id,
            actor_type: ActorType::Human,
            instance_id: None,
            public_keys: vec![PublicKey {
                key_id: cred.credential_id.clone(),
                algorithm: cred.algorithm.clone(),
                public_key: cred.public_key.clone(),
                purpose: PublicKey_Purpose::Signing,
                valid_from: cred.valid_from.clone(),
                valid_until: cred.valid_until.clone(),
            }],
            trust_levels: vec![TrustLevel::T4],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::HardwareKey,
                id: cred
                    .aaguid
                    .clone()
                    .unwrap_or_else(|| "(unknown-aaguid)".to_string()),
            }],
            attestations: None,
            valid_from: cred.valid_from.clone().unwrap_or(now),
            valid_until: cred.valid_until.clone(),
            revocation_ref: None,
            signature: None,
        };
        Ok(identity)
    }

    /// Reverse projection. Mirrors TS `WebAuthnBridge.project`.
    pub fn project(&self, identity: &ActorIdentity) -> Result<WebAuthnCredential, BridgeError> {
        if !matches!(identity.actor_type, ActorType::Human) {
            return Err(BridgeError::Unsupported(format!(
                "WebAuthn bridge only reverses human actors, got {:?}",
                identity.actor_type
            )));
        }
        let hardware_root = identity
            .authority_roots
            .iter()
            .find(|r| matches!(r.kind, AuthorityRoot_Kind::HardwareKey))
            .ok_or_else(|| {
                BridgeError::Rejected(
                    "identity's authority_roots does not include hardware-key".into(),
                )
            })?;
        let key = identity
            .public_keys
            .first()
            .ok_or_else(|| BridgeError::InvalidInput("identity has no public_keys".into()))?;
        let (rp_id, user_handle) = parse_actor_uri(&identity.actor_id)?;
        Ok(WebAuthnCredential {
            credential_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            algorithm: key.algorithm.clone(),
            rp_id,
            user_handle,
            aaguid: if hardware_root.id == "(unknown-aaguid)" {
                None
            } else {
                Some(hardware_root.id.clone())
            },
            attestation_format: None,
            valid_from: Some(identity.valid_from.clone()),
            valid_until: identity.valid_until.clone(),
        })
    }
}

impl Bridge for WebAuthnBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Webauthn
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn slug(b64url: &str) -> String {
    b64url
        .trim_end_matches('=')
        .replace('/', "_")
        .replace('+', "-")
}

fn parse_actor_uri(uri: &str) -> Result<(String, String), BridgeError> {
    // Matches `tf:actor:human:<rp_id>/<user_handle>`.
    let rest = uri
        .strip_prefix("tf:actor:human:")
        .ok_or_else(|| BridgeError::InvalidInput(format!("malformed actor URI: {}", uri)))?;
    let slash = rest
        .find('/')
        .ok_or_else(|| BridgeError::InvalidInput(format!("malformed actor URI: {}", uri)))?;
    Ok((rest[..slash].to_string(), rest[slash + 1..].to_string()))
}

fn current_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (year, month, day, hour, minute, second) = civil_from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn civil_from_unix(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
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
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}

