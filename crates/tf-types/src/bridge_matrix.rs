//! Matrix bridge — Rust mirror.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bridges::{Bridge, BridgeError, BridgeKind};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixEvent {
    pub event_id: String,
    pub room_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub sender: String,
    pub origin_server_ts: i64,
    pub content: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct MatrixBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub default_level: Option<String>,
}

pub struct MatrixBridge {
    cfg: MatrixBridgeConfig,
}

impl MatrixBridge {
    pub fn new(cfg: MatrixBridgeConfig) -> Self {
        MatrixBridge { cfg }
    }

    pub fn matrix_event_to_proof_event(&self, m: &MatrixEvent) -> Result<Value, BridgeError> {
        if m.event_id.is_empty() || m.sender.is_empty() || m.kind.is_empty() {
            return Err(BridgeError::InvalidInput(
                "Matrix event missing event_id / sender / type".into(),
            ));
        }
        let actor = map_sender(&m.sender)?;
        let timestamp = ms_to_iso8601(m.origin_server_ts);
        let from_message = m.kind == "m.room.message";
        let tf_type = if from_message {
            "matrix.message".to_string()
        } else if let Some(rest) = m.kind.strip_prefix("m.") {
            format!("matrix.{}", rest)
        } else {
            m.kind.clone()
        };
        Ok(json!({
            "event_version": "1",
            "id": m.event_id,
            "type": tf_type,
            "actor_id": actor,
            "timestamp": timestamp,
            "level": self.cfg.default_level.clone().unwrap_or_else(|| "L1".into()),
            "context": {
                "matrix": {
                    "room_id": m.room_id,
                    "state_key": m.state_key,
                    "content": m.content,
                    "server_signatures": m.signatures,
                }
            },
            "signature": { "algorithm": "ed25519", "signer": actor, "signature": "AAAA" }
        }))
    }
}

impl Bridge for MatrixBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Matrix
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

pub fn map_sender(sender: &str) -> Result<String, BridgeError> {
    let rest = sender.strip_prefix('@').ok_or_else(|| {
        BridgeError::InvalidInput(format!("cannot map non-Matrix sender: {}", sender))
    })?;
    let colon = rest.find(':').ok_or_else(|| {
        BridgeError::InvalidInput(format!("cannot map non-Matrix sender: {}", sender))
    })?;
    let local = &rest[..colon];
    let server = &rest[colon + 1..];
    Ok(format!("tf:actor:human:{}/{}", server, local))
}

fn ms_to_iso8601(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
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
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}
