//! Dynamic permission negotiation helpers — Rust mirror of
//! `tools/tf-types-ts/src/core/permission.ts`.

use crate::encoding::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;
use crate::expiration::{is_within_window, Window};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionRequest {
    pub request_version: String,
    pub id: String,
    pub agent: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub danger_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_seconds: Option<u64>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof_level_offered: Option<String>,
    pub requested_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionGrant {
    pub grant_version: String,
    pub request_id: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub capability: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub constraints: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy_decision: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ceremony_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denial_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<String>,
    pub issued_at: String,
    pub issuer: String,
    pub signature: SignatureEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct VerifyPermissionGrantResult {
    pub ok: bool,
    pub reason: Option<String>,
}

pub fn permission_grant_signing_bytes(grant: &PermissionGrant) -> [u8; 32] {
    let mut value = serde_json::to_value(grant).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

#[allow(clippy::too_many_arguments)]
pub fn sign_permission_grant(
    request: &PermissionRequest,
    decision: &str,
    issuer: &str,
    private_key: &[u8; 32],
    capability: Option<Value>,
    constraints: Option<Vec<Value>>,
    policy_decision: Option<Value>,
    ceremony_id: Option<String>,
    denial_reason: Option<String>,
    issued_at: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
) -> PermissionGrant {
    let issued_at = issued_at.unwrap_or_else(now_iso8601);
    let mut grant = PermissionGrant {
        grant_version: "1".into(),
        request_id: request.id.clone(),
        decision: decision.into(),
        capability,
        constraints: constraints.filter(|c| !c.is_empty()),
        policy_decision,
        ceremony_id,
        denial_reason,
        valid_from,
        valid_until,
        issued_at,
        issuer: issuer.into(),
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: issuer.into(),
            signature: String::new(),
        },
    };
    let digest = permission_grant_signing_bytes(&grant);
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(&digest);
    grant.signature.signature = STANDARD.encode(sig.to_bytes());
    grant
}

pub fn verify_permission_grant(
    grant: &PermissionGrant,
    public_key: &[u8; 32],
    request: Option<&PermissionRequest>,
    now: Option<&str>,
) -> VerifyPermissionGrantResult {
    if grant.grant_version != "1" {
        return rejected(format!("unsupported grant_version {}", grant.grant_version));
    }
    if grant.signature.signer != grant.issuer {
        return rejected("signature signer does not match issuer".into());
    }
    if grant.signature.algorithm != "ed25519" {
        return rejected(format!(
            "unsupported signature algorithm {}",
            grant.signature.algorithm
        ));
    }
    if let Some(req) = request {
        if grant.request_id != req.id {
            return rejected("grant.request_id does not match request.id".into());
        }
    }
    let now_string = now.map(str::to_string).unwrap_or_else(now_iso8601);
    let window = Window {
        valid_from: grant.valid_from.as_deref(),
        valid_until: grant.valid_until.as_deref(),
        ..Window::default()
    };
    if !is_within_window(&window, &now_string) {
        return rejected("grant outside valid_from/valid_until window".into());
    }
    let digest = permission_grant_signing_bytes(grant);
    let sig_bytes = match STANDARD.decode(&grant.signature.signature) {
        Ok(b) => b,
        Err(e) => return rejected(format!("signature base64 decode: {}", e)),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return rejected(format!("signature parse: {}", e)),
    };
    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(v) => v,
        Err(e) => return rejected(format!("verifying key: {}", e)),
    };
    if vk.verify(&digest, &sig).is_err() {
        return rejected("grant signature did not verify".into());
    }
    VerifyPermissionGrantResult {
        ok: true,
        reason: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requested_action: Option<String>,
}

pub fn provenance_from_request(req: &PermissionRequest) -> Provenance {
    Provenance {
        human: req.human.clone(),
        agent: Some(req.agent.clone()),
        instance: req.instance.clone(),
        model: req.model.clone(),
        tool: req.tool.clone(),
        requested_action: Some(req.action.clone()),
    }
}

fn rejected(reason: String) -> VerifyPermissionGrantResult {
    VerifyPermissionGrantResult {
        ok: false,
        reason: Some(reason),
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (y, m, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

fn secs_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
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
    (year as i32, m, d, hour, minute, second)
}
