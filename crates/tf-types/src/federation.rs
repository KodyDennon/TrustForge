//! Federation primitives — Rust mirror of TS `federation.ts`.

use crate::encoding::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;
use crate::expiration::{is_within_window, Window};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustBundleEntry {
    pub kind: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationAttestation {
    pub attestation_version: String,
    pub attestation_id: String,
    pub issuer_domain: String,
    pub subject_domain: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject_actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trust_levels_granted: Option<Vec<String>>,
    pub trust_bundle: Vec<TrustBundleEntry>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub constraints: Option<Vec<Value>>,
    pub issued_at: String,
    pub valid_until: String,
    pub issuer: String,
    pub signature: SignatureEnvelope,
}

pub fn attestation_signing_bytes(a: &FederationAttestation) -> [u8; 32] {
    let mut value = serde_json::to_value(a).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

#[derive(Clone, Debug)]
pub struct SignAttestationArgs {
    pub attestation_id: String,
    pub issuer_domain: String,
    pub subject_domain: String,
    pub subject_actor: Option<String>,
    pub scope: Option<Vec<String>>,
    pub trust_levels_granted: Option<Vec<String>>,
    pub trust_bundle: Vec<TrustBundleEntry>,
    pub constraints: Option<Vec<Value>>,
    pub issued_at: Option<String>,
    pub valid_until: String,
    pub issuer: String,
    pub private_key: [u8; 32],
}

pub fn sign_federation_attestation(
    args: SignAttestationArgs,
) -> Result<FederationAttestation, String> {
    if args.trust_bundle.is_empty() {
        return Err("trust_bundle must be non-empty".into());
    }
    let mut att = FederationAttestation {
        attestation_version: "1".into(),
        attestation_id: args.attestation_id,
        issuer_domain: args.issuer_domain,
        subject_domain: args.subject_domain,
        subject_actor: args.subject_actor,
        scope: args.scope.filter(|s| !s.is_empty()),
        trust_levels_granted: args.trust_levels_granted.filter(|s| !s.is_empty()),
        trust_bundle: args.trust_bundle,
        constraints: args.constraints.filter(|s| !s.is_empty()),
        issued_at: args.issued_at.unwrap_or_else(now_iso8601),
        valid_until: args.valid_until,
        issuer: args.issuer.clone(),
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: args.issuer,
            signature: String::new(),
        },
    };
    let digest = attestation_signing_bytes(&att);
    let signing = SigningKey::from_bytes(&args.private_key);
    let sig: Signature = signing.sign(&digest);
    att.signature.signature = STANDARD.encode(sig.to_bytes());
    Ok(att)
}

#[derive(Debug)]
pub struct VerifyAttestationResult {
    pub ok: bool,
    pub reason: Option<String>,
}

pub fn verify_federation_attestation(
    a: &FederationAttestation,
    issuer_public_key: &[u8; 32],
    now: Option<&str>,
) -> VerifyAttestationResult {
    let rejected = |r: &str| VerifyAttestationResult {
        ok: false,
        reason: Some(r.to_string()),
    };
    if a.attestation_version != "1" {
        return rejected(&format!("unsupported version {}", a.attestation_version));
    }
    if a.signature.signer != a.issuer {
        return rejected("signature signer does not match issuer");
    }
    if a.signature.algorithm != "ed25519" {
        return rejected(&format!("unsupported algorithm {}", a.signature.algorithm));
    }
    let now_string = now.map(str::to_string).unwrap_or_else(now_iso8601);
    let window = Window {
        valid_from: Some(a.issued_at.as_str()),
        valid_until: Some(a.valid_until.as_str()),
        ..Window::default()
    };
    if !is_within_window(&window, &now_string) {
        return rejected("attestation outside valid window");
    }
    let digest = attestation_signing_bytes(a);
    let sig_bytes = match STANDARD.decode(&a.signature.signature) {
        Ok(b) => b,
        Err(e) => return rejected(&format!("signature base64: {}", e)),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return rejected(&format!("signature parse: {}", e)),
    };
    let vk = match VerifyingKey::from_bytes(issuer_public_key) {
        Ok(v) => v,
        Err(e) => return rejected(&format!("verifying key: {}", e)),
    };
    if vk.verify(&digest, &sig).is_err() {
        return rejected("signature did not verify");
    }
    VerifyAttestationResult {
        ok: true,
        reason: None,
    }
}

#[derive(Default)]
pub struct FederatedTrustStore {
    by_id: std::collections::HashMap<String, FederationAttestation>,
}

impl FederatedTrustStore {
    pub fn new() -> Self {
        FederatedTrustStore::default()
    }

    pub fn add(&mut self, att: FederationAttestation) {
        self.by_id.insert(att.attestation_id.clone(), att);
    }

    pub fn remove(&mut self, attestation_id: &str) -> bool {
        self.by_id.remove(attestation_id).is_some()
    }

    pub fn list(&self) -> Vec<&FederationAttestation> {
        self.by_id.values().collect()
    }

    pub fn find_for(
        &self,
        actor: &str,
        subject_domain: &str,
        now: Option<&str>,
    ) -> Option<&FederationAttestation> {
        let now_string = now.map(str::to_string).unwrap_or_else(now_iso8601);
        for a in self.by_id.values() {
            if a.subject_domain != subject_domain {
                continue;
            }
            if let Some(s) = &a.subject_actor {
                if s != actor {
                    continue;
                }
            }
            let window = Window {
                valid_from: Some(a.issued_at.as_str()),
                valid_until: Some(a.valid_until.as_str()),
                ..Window::default()
            };
            if !is_within_window(&window, &now_string) {
                continue;
            }
            return Some(a);
        }
        None
    }

    pub fn verify_foreign(
        &self,
        actor: &str,
        subject_domain: &str,
        signed: Option<(&[u8], &[u8])>,
        now: Option<&str>,
    ) -> ForeignIdentityCheck {
        let a = match self.find_for(actor, subject_domain, now) {
            Some(a) => a,
            None => {
                return ForeignIdentityCheck {
                    ok: false,
                    reason: Some(format!(
                        "no active attestation for {} in {}",
                        actor, subject_domain
                    )),
                    matched_attestation_id: None,
                    trust_levels: None,
                    scope: None,
                };
            }
        };
        if let Some((message, sig_bytes)) = signed {
            let sig = match Signature::from_slice(sig_bytes) {
                Ok(s) => s,
                Err(e) => {
                    return ForeignIdentityCheck {
                        ok: false,
                        reason: Some(format!("foreign sig parse: {}", e)),
                        matched_attestation_id: Some(a.attestation_id.clone()),
                        trust_levels: None,
                        scope: None,
                    };
                }
            };
            let mut matched = false;
            for entry in &a.trust_bundle {
                if entry.kind != "ed25519" {
                    continue;
                }
                let pk_bytes = match STANDARD.decode(&entry.value) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if pk_bytes.len() != 32 {
                    continue;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&pk_bytes);
                if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                    if vk.verify(message, &sig).is_ok() {
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return ForeignIdentityCheck {
                    ok: false,
                    reason: Some("no bundle key matched the foreign actor's signature".into()),
                    matched_attestation_id: Some(a.attestation_id.clone()),
                    trust_levels: None,
                    scope: None,
                };
            }
        }
        ForeignIdentityCheck {
            ok: true,
            reason: None,
            matched_attestation_id: Some(a.attestation_id.clone()),
            trust_levels: a.trust_levels_granted.clone(),
            scope: a.scope.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ForeignIdentityCheck {
    pub ok: bool,
    pub reason: Option<String>,
    pub matched_attestation_id: Option<String>,
    pub trust_levels: Option<Vec<String>>,
    pub scope: Option<Vec<String>>,
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
