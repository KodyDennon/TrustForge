//! Offline-signed approval packets — Rust mirror of
//! `tools/tf-types-ts/src/core/offline-approval.ts`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineApprovalPacket {
    pub packet_version: String,
    pub request: Value,
    pub decision: String,
    pub responder: String,
    pub responded_at: String,
    pub transport_hint: String,
    pub signature: SignatureEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineApprovalCeremony {
    pub ceremony_version: String,
    pub ceremony_id: String,
    pub kind: String,
    pub request_id: String,
    pub responder: String,
    pub packet_id: String,
    pub transport_hint: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub response_version: String,
    pub request_id: String,
    pub decision: String,
    pub responder: String,
    pub signed_at: String,
    pub signature: SignatureEnvelope,
}

#[derive(Debug)]
pub struct VerifyOfflineApprovalResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub response: Option<ApprovalResponse>,
    pub ceremony: Option<OfflineApprovalCeremony>,
}

pub fn sign_offline_approval_packet(
    request: Value,
    decision: &str,
    responder: &str,
    private_key: &[u8; 32],
    transport_hint: &str,
    responded_at: Option<&str>,
) -> OfflineApprovalPacket {
    let responded_at = responded_at
        .map(str::to_string)
        .unwrap_or_else(now_iso8601);
    let payload_value = serde_json::json!({
        "request": request,
        "decision": decision,
        "responder": responder,
        "responded_at": responded_at,
    });
    let canonical = canonicalize(&payload_value).unwrap_or_default();
    let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(&digest);
    OfflineApprovalPacket {
        packet_version: "1".into(),
        request,
        decision: decision.into(),
        responder: responder.into(),
        responded_at,
        transport_hint: transport_hint.into(),
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: responder.into(),
            signature: STANDARD.encode(sig.to_bytes()),
        },
    }
}

pub fn verify_offline_approval_packet(
    packet: &OfflineApprovalPacket,
    public_key: &[u8; 32],
    now: Option<&str>,
    max_age_seconds: Option<i64>,
) -> VerifyOfflineApprovalResult {
    if packet.packet_version != "1" {
        return rejected(format!(
            "unsupported packet_version {}",
            packet.packet_version
        ));
    }
    if packet.signature.signer != packet.responder {
        return rejected("signature signer does not match responder".into());
    }
    if packet.signature.algorithm != "ed25519" {
        return rejected(format!(
            "unsupported signature algorithm {}",
            packet.signature.algorithm
        ));
    }
    let max = max_age_seconds.unwrap_or(86_400);
    if let (Some(now_str), Ok(then_secs)) = (now, parse_iso8601(&packet.responded_at)) {
        if let Ok(now_secs) = parse_iso8601(now_str) {
            let age = now_secs - then_secs;
            if age > max {
                return rejected(format!("packet older than {}s", max));
            }
            if age < -300 {
                return rejected("packet timestamp is in the future".into());
            }
        }
    }
    let payload_value = serde_json::json!({
        "request": packet.request,
        "decision": packet.decision,
        "responder": packet.responder,
        "responded_at": packet.responded_at,
    });
    let canonical = canonicalize(&payload_value).unwrap_or_default();
    let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    let sig_bytes = match STANDARD.decode(&packet.signature.signature) {
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
        return rejected("signature verification failed".into());
    }
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    let packet_id = format!("pkt-{}", &hex[..16]);
    let request_id = packet
        .request
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let response = ApprovalResponse {
        response_version: "1".into(),
        request_id: request_id.clone(),
        decision: packet.decision.clone(),
        responder: packet.responder.clone(),
        signed_at: packet.responded_at.clone(),
        signature: packet.signature.clone(),
    };
    let ceremony = OfflineApprovalCeremony {
        ceremony_version: "1".into(),
        ceremony_id: format!("cer-{}", packet_id),
        kind: "offline-signed-packet".into(),
        request_id,
        responder: packet.responder.clone(),
        packet_id,
        transport_hint: packet.transport_hint.clone(),
        signature: packet.signature.signature.clone(),
    };
    VerifyOfflineApprovalResult {
        ok: true,
        reason: None,
        response: Some(response),
        ceremony: Some(ceremony),
    }
}

fn rejected(reason: String) -> VerifyOfflineApprovalResult {
    VerifyOfflineApprovalResult {
        ok: false,
        reason: Some(reason),
        response: None,
        ceremony: None,
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

fn parse_iso8601(s: &str) -> Result<i64, ()> {
    if s.len() < 19 || !s.ends_with('Z') {
        return Err(());
    }
    let year: i64 = s[..4].parse().map_err(|_| ())?;
    let month: u32 = s[5..7].parse().map_err(|_| ())?;
    let day: u32 = s[8..10].parse().map_err(|_| ())?;
    let hour: u32 = s[11..13].parse().map_err(|_| ())?;
    let minute: u32 = s[14..16].parse().map_err(|_| ())?;
    let second: u32 = s[17..19].parse().map_err(|_| ())?;
    Ok(unix_from_civil(year, month, day, hour, minute, second))
}

fn unix_from_civil(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
    // Howard Hinnant days_from_civil
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64
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
