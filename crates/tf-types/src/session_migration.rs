//! Session-migration helpers (Rust mirror of TS).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportBinding {
    pub binding_version: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exporter_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub peer_cert_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tls_alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub established_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMigration {
    pub migration_version: String,
    pub session_id: String,
    pub generation: u64,
    pub from_binding: TransportBinding,
    pub to_binding: TransportBinding,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preserved_capabilities: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rotated_keys: Option<bool>,
    pub migrated_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    pub signer: String,
    pub signature: SignatureEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

pub fn migration_signing_bytes(m: &SessionMigration) -> [u8; 32] {
    let mut value = serde_json::to_value(m).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

#[allow(clippy::too_many_arguments)]
pub fn migrate_session(
    session_id: &str,
    generation: u64,
    from_binding: TransportBinding,
    to_binding: TransportBinding,
    rotated_keys: bool,
    reason: Option<&str>,
    signer: &str,
    private_key: &[u8; 32],
    migrated_at: Option<&str>,
) -> SessionMigration {
    let migrated_at = migrated_at.map(str::to_string).unwrap_or_else(now_iso8601);
    let mut m = SessionMigration {
        migration_version: "1".into(),
        session_id: session_id.into(),
        generation,
        from_binding,
        to_binding,
        preserved_capabilities: None,
        rotated_keys: if rotated_keys { Some(true) } else { None },
        migrated_at,
        reason: reason.map(str::to_string),
        signer: signer.into(),
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: signer.into(),
            signature: String::new(),
        },
    };
    let digest = migration_signing_bytes(&m);
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(&digest);
    m.signature.signature = STANDARD.encode(sig.to_bytes());
    m
}

#[derive(Debug)]
pub struct VerifyMigrationResult {
    pub ok: bool,
    pub reason: Option<String>,
}

pub fn verify_session_migration(
    m: &SessionMigration,
    public_key: &[u8; 32],
    last_generation: Option<u64>,
    expected_session_id: Option<&str>,
) -> VerifyMigrationResult {
    let rejected = |r: &str| VerifyMigrationResult {
        ok: false,
        reason: Some(r.to_string()),
    };
    if m.migration_version != "1" {
        return rejected(&format!(
            "unsupported migration_version {}",
            m.migration_version
        ));
    }
    if m.signature.signer != m.signer {
        return rejected("signature signer does not match signer");
    }
    if m.signature.algorithm != "ed25519" {
        return rejected(&format!(
            "unsupported signature algorithm {}",
            m.signature.algorithm
        ));
    }
    if let Some(expected) = expected_session_id {
        if m.session_id != expected {
            return rejected("session_id mismatch");
        }
    }
    if let Some(last) = last_generation {
        if m.generation <= last {
            return rejected(&format!(
                "generation {} <= last seen {} (replay)",
                m.generation, last
            ));
        }
    }
    let digest = migration_signing_bytes(m);
    let sig_bytes = match STANDARD.decode(&m.signature.signature) {
        Ok(b) => b,
        Err(e) => return rejected(&format!("signature base64 decode: {}", e)),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return rejected(&format!("signature parse: {}", e)),
    };
    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(v) => v,
        Err(e) => return rejected(&format!("verifying key: {}", e)),
    };
    if vk.verify(&digest, &sig).is_err() {
        return rejected("migration signature did not verify");
    }
    VerifyMigrationResult {
        ok: true,
        reason: None,
    }
}

const RATCHET_INFO: &[u8] = b"tf-session/ratchet";

#[derive(Debug)]
pub struct Ratchet {
    current_key: [u8; 32],
    rotation_count: u64,
    messages_since_rotation: u32,
    max_messages: u32,
}

impl Ratchet {
    pub fn new(initial_key: [u8; 32], max_messages: Option<u32>) -> Self {
        Ratchet {
            current_key: initial_key,
            rotation_count: 0,
            messages_since_rotation: 0,
            max_messages: max_messages.unwrap_or(1024),
        }
    }

    pub fn key(&self) -> [u8; 32] {
        self.current_key
    }

    pub fn generation(&self) -> u64 {
        self.rotation_count
    }

    pub fn observe_message(&mut self) -> bool {
        self.messages_since_rotation += 1;
        if self.messages_since_rotation >= self.max_messages {
            self.rotate();
            true
        } else {
            false
        }
    }

    pub fn rotate(&mut self) {
        let hk = Hkdf::<Sha256>::new(None, &self.current_key);
        let mut next = [0u8; 32];
        hk.expand(RATCHET_INFO, &mut next).expect("hkdf");
        self.current_key = next;
        self.rotation_count += 1;
        self.messages_since_rotation = 0;
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
