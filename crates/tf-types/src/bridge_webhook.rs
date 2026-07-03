//! Webhook bridge — Rust mirror. HMAC-SHA256, HMAC-SHA1, and ed25519
//! signature schemes; vendor-event → action mapping; replay-window.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::Sha256;

use crate::bridges::{Bridge, BridgeError, BridgeKind};

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WebhookScheme {
    HmacSha256,
    HmacSha1,
    Ed25519,
}

#[derive(Clone, Debug)]
pub struct WebhookBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub vendor: String,
    pub scheme: WebhookScheme,
    pub secret: Vec<u8>,
    pub max_age_seconds: Option<i64>,
    pub default_risk: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VerifyWebhookArgs {
    pub body: Vec<u8>,
    pub signature_header: String,
    pub timestamp_header: Option<String>,
    pub event_type: String,
    pub event_id: String,
    pub received_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WebhookVerificationResult {
    pub event: Value,
    pub capability: Value,
}

pub struct WebhookBridge {
    cfg: WebhookBridgeConfig,
}

impl WebhookBridge {
    pub fn new(cfg: WebhookBridgeConfig) -> Self {
        WebhookBridge { cfg }
    }

    pub fn verify(
        &self,
        args: VerifyWebhookArgs,
    ) -> Result<WebhookVerificationResult, BridgeError> {
        let now_str = args.received_at.clone().unwrap_or_else(now_iso8601);
        let ok = match self.cfg.scheme {
            WebhookScheme::HmacSha256 => {
                let mut mac = HmacSha256::new_from_slice(&self.cfg.secret)
                    .map_err(|e| BridgeError::InvalidInput(format!("hmac: {}", e)))?;
                mac.update(&args.body);
                let computed = mac.finalize().into_bytes();
                let expected = hex(&computed);
                let provided = args
                    .signature_header
                    .to_lowercase()
                    .trim_start_matches("sha256=")
                    .to_string();
                constant_time_eq_hex(&expected, &provided)
            }
            WebhookScheme::HmacSha1 => {
                let mut mac = HmacSha1::new_from_slice(&self.cfg.secret)
                    .map_err(|e| BridgeError::InvalidInput(format!("hmac: {}", e)))?;
                mac.update(&args.body);
                let computed = mac.finalize().into_bytes();
                let expected = hex(&computed);
                let provided = args
                    .signature_header
                    .to_lowercase()
                    .trim_start_matches("sha1=")
                    .to_string();
                constant_time_eq_hex(&expected, &provided)
            }
            WebhookScheme::Ed25519 => {
                let ts = args.timestamp_header.as_ref().ok_or_else(|| {
                    BridgeError::InvalidInput("ed25519 webhook requires timestamp header".into())
                })?;
                let mut payload = Vec::with_capacity(ts.len() + 1 + args.body.len());
                payload.extend_from_slice(ts.as_bytes());
                payload.push(b'.');
                payload.extend_from_slice(&args.body);
                let sig_bytes = decode_hex(&args.signature_header)
                    .ok_or_else(|| BridgeError::InvalidInput("signature header not hex".into()))?;
                let pk_arr: [u8; 32] = self.cfg.secret.as_slice().try_into().map_err(|_| {
                    BridgeError::InvalidInput("ed25519 public key must be 32 bytes".into())
                })?;
                let vk = VerifyingKey::from_bytes(&pk_arr)
                    .map_err(|e| BridgeError::InvalidInput(format!("ed25519 key: {}", e)))?;
                let sig = Signature::from_slice(&sig_bytes)
                    .map_err(|e| BridgeError::InvalidInput(format!("signature parse: {}", e)))?;
                vk.verify(&payload, &sig).is_ok()
            }
        };
        if !ok {
            return Err(BridgeError::Rejected(format!(
                "webhook signature failed ({:?})",
                self.cfg.scheme
            )));
        }
        let max = self.cfg.max_age_seconds.unwrap_or(300);
        if let Some(ts) = &args.timestamp_header {
            let ts_str = if ts.contains('T') {
                ts.clone()
            } else {
                let secs = ts.parse::<i64>().unwrap_or(0);
                let (y, m, d, h, mi, s) = secs_to_ymdhms(secs);
                format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
            };
            if let (Some(t1), Some(t2)) = (parse_iso8601(&ts_str), parse_iso8601(&now_str)) {
                let age = (t2 - t1).abs();
                if age > max {
                    return Err(BridgeError::Rejected(format!(
                        "webhook age {}s exceeds {}s",
                        age, max
                    )));
                }
            }
        }
        let actor = format!(
            "tf:actor:service:{}/{}",
            self.cfg.trust_domain, self.cfg.vendor
        );
        let action = format!(
            "webhook.{}.{}",
            self.cfg.vendor,
            args.event_type.replace(
                |c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-',
                "_"
            )
        );
        let event = json!({
            "event_version": "1",
            "id": args.event_id,
            "type": action,
            "actor_id": actor,
            "timestamp": now_str,
            "level": "L2",
            "context": {
                "vendor": self.cfg.vendor,
                "scheme": format!("{:?}", self.cfg.scheme),
                "event_type": args.event_type,
            },
            "signature": { "algorithm": "ed25519", "signer": actor, "signature": "AAAA" }
        });
        let capability = json!({
            "name": action,
            "risk": self.cfg.default_risk.clone().unwrap_or_else(|| "R2".to_string()),
        });
        Ok(WebhookVerificationResult { event, capability })
    }
}

impl Bridge for WebhookBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Webhook
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim().to_lowercase().trim_start_matches("0x").to_string();
    let trimmed = trimmed
        .trim_start_matches("sha256=")
        .trim_start_matches("sha1=");
    if !trimmed.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for i in (0..trimmed.len()).step_by(2) {
        out.push(u8::from_str_radix(&trimmed[i..i + 2], 16).ok()?);
    }
    Some(out)
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn parse_iso8601(s: &str) -> Option<i64> {
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s[..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: u32 = s[11..13].parse().ok()?;
    let minute: u32 = s[14..16].parse().ok()?;
    let second: u32 = s[17..19].parse().ok()?;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    Some(days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64)
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
