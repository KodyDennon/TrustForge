//! Compliance evidence pipeline (TF-0012) — Rust mirror of
//! `tools/tf-types-ts/src/core/evidence.ts`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceIncident {
    pub label: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub evidence_version: String,
    pub bundle_id: String,
    pub trust_domain: String,
    pub incident: EvidenceIncident,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub actors: Option<Vec<String>>,
    pub events: Vec<Value>,
    pub policy_decisions: Vec<Value>,
    pub approvals: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ceremonies: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub quorum_outcomes: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub anchors: Option<Vec<EvidenceAnchor>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encrypted_payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub level: Option<String>,
    pub issued_at: String,
    pub issuer: String,
    pub signature: SignatureEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAnchor {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub inclusion_proof: Option<Value>,
}

pub fn evidence_signing_bytes(b: &EvidenceBundle) -> [u8; 32] {
    let mut value = serde_json::to_value(b).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

#[derive(Clone, Debug, Default)]
pub struct AssembleArgs {
    pub bundle_id: String,
    pub trust_domain: String,
    pub label: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub domains: Option<Vec<String>>,
    pub description: Option<String>,
    pub actor_filter: Option<Vec<String>>,
    pub event_type_pattern: Option<String>,
    pub policy_decisions: Vec<Value>,
    pub approvals: Vec<Value>,
    pub ceremonies: Option<Vec<Value>>,
    pub quorum_outcomes: Option<Vec<Value>>,
    pub issuer: String,
    pub private_key: [u8; 32],
}

#[derive(Debug)]
pub struct AssembleResult {
    pub bundle: EvidenceBundle,
    pub skipped: usize,
}

pub fn assemble_evidence_bundle(
    events: &[Value],
    args: AssembleArgs,
) -> Result<AssembleResult, String> {
    let actor_set: Option<std::collections::HashSet<String>> = args
        .actor_filter
        .as_ref()
        .map(|a| a.iter().cloned().collect());
    let regex = match args.event_type_pattern.as_deref() {
        Some(p) => Some(regex::Regex::new(p).map_err(|e| format!("type pattern: {}", e))?),
        None => None,
    };
    let mut skipped = 0usize;
    let mut filtered = Vec::new();
    for ev in events {
        let ts = ev.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        if ts < args.started_at.as_str() {
            skipped += 1;
            continue;
        }
        if let Some(end) = &args.ended_at {
            if ts > end.as_str() {
                skipped += 1;
                continue;
            }
        }
        if let Some(set) = &actor_set {
            let actor = ev.get("actor_id").and_then(|v| v.as_str()).unwrap_or("");
            if !set.contains(actor) {
                skipped += 1;
                continue;
            }
        }
        if let Some(re) = &regex {
            let typ = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if !re.is_match(typ) {
                skipped += 1;
                continue;
            }
        }
        filtered.push(ev.clone());
    }
    if filtered.is_empty() {
        return Err("evidence bundle requires at least one matching event".into());
    }
    let mut actors: Vec<String> = filtered
        .iter()
        .filter_map(|ev| {
            ev.get("actor_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .collect();
    actors.sort();
    actors.dedup();
    let level = highest_level(&filtered);

    let mut bundle = EvidenceBundle {
        evidence_version: "1".into(),
        bundle_id: args.bundle_id,
        trust_domain: args.trust_domain,
        incident: EvidenceIncident {
            label: args.label,
            started_at: args.started_at,
            ended_at: args.ended_at,
            domains: args.domains,
            description: args.description,
        },
        actors: Some(actors),
        events: filtered,
        policy_decisions: args.policy_decisions,
        approvals: args.approvals,
        ceremonies: args.ceremonies,
        quorum_outcomes: args.quorum_outcomes,
        anchors: None,
        encrypted_payload: None,
        level: Some(level),
        issued_at: now_iso8601(),
        issuer: args.issuer.clone(),
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: args.issuer,
            signature: String::new(),
        },
    };
    let digest = evidence_signing_bytes(&bundle);
    let signing = SigningKey::from_bytes(&args.private_key);
    let sig: Signature = signing.sign(&digest);
    bundle.signature.signature = STANDARD.encode(sig.to_bytes());
    Ok(AssembleResult { bundle, skipped })
}

fn highest_level(events: &[Value]) -> String {
    let order = ["L0", "L1", "L2", "L3", "L4", "L5"];
    let mut max = 0usize;
    for ev in events {
        let lvl = ev.get("level").and_then(|v| v.as_str()).unwrap_or("L0");
        if let Some(idx) = order.iter().position(|x| *x == lvl) {
            if idx > max {
                max = idx;
            }
        }
    }
    order[max].into()
}

#[derive(Debug, Default)]
pub struct VerifyResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub outer_signature_ok: bool,
    pub events_verified: usize,
    pub events_skipped: usize,
}

pub fn verify_evidence_bundle(
    bundle: &EvidenceBundle,
    issuer_public_key: &[u8; 32],
) -> VerifyResult {
    let mut result = VerifyResult::default();
    let digest = evidence_signing_bytes(bundle);
    let sig_bytes = match STANDARD.decode(&bundle.signature.signature) {
        Ok(b) => b,
        Err(e) => {
            result.reason = Some(format!("signature base64: {}", e));
            return result;
        }
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            result.reason = Some(format!("signature parse: {}", e));
            return result;
        }
    };
    let vk = match VerifyingKey::from_bytes(issuer_public_key) {
        Ok(v) => v,
        Err(e) => {
            result.reason = Some(format!("verifying key: {}", e));
            return result;
        }
    };
    if vk.verify(&digest, &sig).is_err() {
        result.reason = Some("outer signature did not verify".into());
        return result;
    }
    result.outer_signature_ok = true;
    result.ok = true;
    result
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
