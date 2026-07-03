#![allow(clippy::unusual_byte_groupings)]
//! Packet mode (TF-0011) — Rust mirror of
//! `tools/tf-types-ts/src/core/packet.ts`.

use crate::encoding::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::canonicalize;
use crate::expiration::{is_within_window, Window};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketSignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketFragmentHeader {
    pub fragment_id: String,
    pub index: u32,
    pub count: u32,
    pub total_payload_bytes: u32,
    pub payload_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Packet {
    pub packet_version: String,
    pub packet_id: String,
    pub source: String,
    pub destination: String,
    pub priority: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub emergency: Option<bool>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl_hops: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub route_constraints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub compression: Option<String>,
    pub payload: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fragment: Option<PacketFragmentHeader>,
    pub signature: PacketSignatureEnvelope,
}

#[derive(Clone, Debug)]
pub struct SignPacketArgs<'a> {
    pub packet_id: String,
    pub source: String,
    pub destination: String,
    pub priority: String,
    pub payload: &'a [u8],
    pub encoding: Option<String>,
    pub compression: Option<String>,
    pub emergency: bool,
    pub expires_at: Option<String>,
    pub ttl_hops: Option<u32>,
    pub route_constraints: Option<Vec<String>>,
    pub session_ref: Option<String>,
    pub private_key: [u8; 32],
    pub signer: String,
    pub created_at: Option<String>,
}

pub fn packet_signing_bytes(p: &Packet) -> [u8; 32] {
    let mut value = serde_json::to_value(p).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

pub fn sign_packet(args: SignPacketArgs<'_>) -> Result<Packet, String> {
    if args.priority == "P0" && !args.emergency {
        return Err("P0 priority is reserved for emergency packets".into());
    }
    let encoding = args.encoding.unwrap_or_else(|| "cbor".to_string());
    let compression = args.compression.unwrap_or_else(|| "none".to_string());

    // Wrap payload in canonical envelope before encoding.
    let payload_bytes: Vec<u8> = if encoding == "cbor" {
        serde_cbor_envelope(args.payload)
    } else {
        let canonical = canonicalize(&serde_json::json!({
            "raw": STANDARD.encode(args.payload),
        }))
        .map_err(|e| format!("canonicalize: {}", e))?;
        canonical.into_bytes()
    };

    let final_bytes = if compression == "deflate" {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&payload_bytes).map_err(|e| e.to_string())?;
        enc.finish().map_err(|e| e.to_string())?
    } else {
        payload_bytes
    };

    let mut draft = Packet {
        packet_version: "1".into(),
        packet_id: args.packet_id,
        source: args.source.clone(),
        destination: args.destination,
        priority: args.priority,
        emergency: if args.emergency { Some(true) } else { None },
        created_at: args.created_at.unwrap_or_else(now_iso8601),
        expires_at: args.expires_at,
        ttl_hops: args.ttl_hops,
        route_constraints: args.route_constraints.filter(|r| !r.is_empty()),
        encoding: Some(encoding),
        compression: Some(compression),
        payload: STANDARD.encode(&final_bytes),
        session_ref: args.session_ref,
        fragment: None,
        signature: PacketSignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: args.signer.clone(),
            signature: String::new(),
        },
    };
    let digest = packet_signing_bytes(&draft);
    let signing = SigningKey::from_bytes(&args.private_key);
    let sig: Signature = signing.sign(&digest);
    draft.signature.signature = STANDARD.encode(sig.to_bytes());
    Ok(draft)
}

#[derive(Debug)]
pub struct VerifyPacketResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub payload: Option<Vec<u8>>,
}

pub fn verify_packet(packet: &Packet, public_key: &[u8; 32], now: &str) -> VerifyPacketResult {
    let rejected = |r: &str| VerifyPacketResult {
        ok: false,
        reason: Some(r.to_string()),
        payload: None,
    };
    if packet.packet_version != "1" {
        return rejected(&format!(
            "unsupported packet_version {}",
            packet.packet_version
        ));
    }
    if packet.signature.signer != packet.source {
        return rejected("signature signer does not match source");
    }
    if packet.priority == "P0" && packet.emergency != Some(true) {
        return rejected("P0 reserved for emergency packets");
    }
    if let Some(expires) = &packet.expires_at {
        let window = Window {
            valid_until: Some(expires.as_str()),
            ..Window::default()
        };
        if !is_within_window(&window, now) {
            return rejected("packet expired");
        }
    }
    let digest = packet_signing_bytes(packet);
    let sig_bytes = match STANDARD.decode(&packet.signature.signature) {
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
        return rejected("signature verification failed");
    }
    let wire = match STANDARD.decode(&packet.payload) {
        Ok(b) => b,
        Err(e) => return rejected(&format!("payload base64: {}", e)),
    };
    let decompressed = if packet.compression.as_deref() == Some("deflate") {
        let mut dec = DeflateDecoder::new(&wire[..]);
        let mut out = Vec::new();
        if dec.read_to_end(&mut out).is_err() {
            return rejected("deflate inflate failed");
        }
        out
    } else {
        wire
    };
    let payload = match packet.encoding.as_deref() {
        Some("json") | None => match serde_json::from_slice::<Value>(&decompressed) {
            Ok(v) => match v.get("raw").and_then(|r| r.as_str()) {
                Some(b64) => match STANDARD.decode(b64) {
                    Ok(b) => b,
                    Err(_) => return rejected("payload base64 inner"),
                },
                None => return rejected("json envelope missing raw"),
            },
            Err(e) => return rejected(&format!("json decode: {}", e)),
        },
        Some("cbor") => match decode_cbor_envelope(&decompressed) {
            Ok(b) => b,
            Err(e) => return rejected(&format!("cbor decode: {}", e)),
        },
        Some(other) => return rejected(&format!("unknown encoding {}", other)),
    };
    VerifyPacketResult {
        ok: true,
        reason: None,
        payload: Some(payload),
    }
}

#[derive(Clone, Debug, Default)]
pub struct FragmentOptions {
    pub mtu: Option<usize>,
}

pub fn fragment_packet(
    source: &Packet,
    private_key: &[u8; 32],
    opts: FragmentOptions,
) -> Vec<Packet> {
    let mtu = opts.mtu.unwrap_or(256);
    let original = STANDARD.decode(&source.payload).unwrap_or_default();
    let total_bytes = original.len();
    if total_bytes <= mtu {
        return vec![source.clone()];
    }
    let count = total_bytes.div_ceil(mtu);
    let digest_hex = sha256_hex(&original);
    let payload_digest = format!("sha256:{}", digest_hex);
    let fragment_id = format!("frag-{}", source.packet_id);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * mtu;
        let end = (start + mtu).min(total_bytes);
        let slice = &original[start..end];
        let mut draft = Packet {
            packet_version: "1".into(),
            packet_id: format!("{}-{}", source.packet_id, i),
            source: source.source.clone(),
            destination: source.destination.clone(),
            priority: source.priority.clone(),
            emergency: source.emergency,
            created_at: source.created_at.clone(),
            expires_at: source.expires_at.clone(),
            ttl_hops: source.ttl_hops,
            route_constraints: source.route_constraints.clone(),
            encoding: source.encoding.clone(),
            compression: source.compression.clone(),
            payload: STANDARD.encode(slice),
            session_ref: source.session_ref.clone(),
            fragment: Some(PacketFragmentHeader {
                fragment_id: fragment_id.clone(),
                index: i as u32,
                count: count as u32,
                total_payload_bytes: total_bytes as u32,
                payload_digest: payload_digest.clone(),
            }),
            signature: PacketSignatureEnvelope {
                algorithm: "ed25519".into(),
                signer: source.source.clone(),
                signature: String::new(),
            },
        };
        let digest = packet_signing_bytes(&draft);
        let signing = SigningKey::from_bytes(private_key);
        let sig: Signature = signing.sign(&digest);
        draft.signature.signature = STANDARD.encode(sig.to_bytes());
        out.push(draft);
    }
    out
}

#[derive(Debug)]
pub struct ReassembleResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub packet_id: Option<String>,
    pub payload: Option<Vec<u8>>,
}

pub fn reassemble_fragments(fragments: &[Packet]) -> ReassembleResult {
    let rejected = |r: &str| ReassembleResult {
        ok: false,
        reason: Some(r.to_string()),
        packet_id: None,
        payload: None,
    };
    if fragments.is_empty() {
        return rejected("no fragments");
    }
    let header = match fragments[0].fragment.as_ref() {
        Some(h) => h.clone(),
        None => return rejected("first fragment missing fragment header"),
    };
    if fragments.len() != header.count as usize {
        return rejected(&format!(
            "expected {} fragments, got {}",
            header.count,
            fragments.len()
        ));
    }
    let mut ordered: Vec<Option<&Packet>> = vec![None; header.count as usize];
    for f in fragments {
        let h = match f.fragment.as_ref() {
            Some(h) => h,
            None => return rejected("fragment missing header"),
        };
        if h.fragment_id != header.fragment_id {
            return rejected("mismatched fragment_id");
        }
        if h.count != header.count {
            return rejected("mismatched fragment count");
        }
        if ordered[h.index as usize].is_some() {
            return rejected(&format!("duplicate fragment index {}", h.index));
        }
        ordered[h.index as usize] = Some(f);
    }
    let mut out = Vec::with_capacity(header.total_payload_bytes as usize);
    for slot in ordered {
        match slot {
            Some(p) => {
                let bytes = match STANDARD.decode(&p.payload) {
                    Ok(b) => b,
                    Err(e) => return rejected(&format!("base64: {}", e)),
                };
                out.extend_from_slice(&bytes);
            }
            None => return rejected("missing fragment slot"),
        }
    }
    if out.len() != header.total_payload_bytes as usize {
        return rejected(&format!(
            "assembled {} bytes, expected {}",
            out.len(),
            header.total_payload_bytes
        ));
    }
    let computed = format!("sha256:{}", sha256_hex(&out));
    if computed != header.payload_digest {
        return rejected("reassembled payload digest mismatch");
    }
    ReassembleResult {
        ok: true,
        reason: None,
        packet_id: Some(header.fragment_id),
        payload: Some(out),
    }
}

fn serde_cbor_envelope(raw: &[u8]) -> Vec<u8> {
    let value = crate::cbor::Value::Map(vec![(
        crate::cbor::Value::Text("raw".into()),
        crate::cbor::Value::Bytes(raw.to_vec()),
    )]);
    crate::cbor::encode(&value).expect("cbor encode")
}

fn decode_cbor_envelope(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::cbor::decode(bytes).map_err(|e| format!("cbor: {}", e))?;
    match value {
        crate::cbor::Value::Map(entries) => {
            for (k, v) in entries {
                if matches!(k, crate::cbor::Value::Text(ref s) if s == "raw") {
                    if let crate::cbor::Value::Bytes(b) = v {
                        return Ok(b);
                    }
                }
            }
            Err("cbor envelope missing raw".into())
        }
        _ => Err("cbor envelope not a map".into()),
    }
}

fn sha256_hex(b: &[u8]) -> String {
    let digest = Sha256::digest(b);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
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

/* ----------------------------------------------------------------------- */
/*  LoRa-style channel simulation (mirror of TS `simulateLora`)            */
/* ----------------------------------------------------------------------- */

#[derive(Clone, Debug, Default)]
pub struct LoraSimOptions {
    /// Per-packet drop probability ∈ [0, 1]. Default 0 (lossless).
    pub packet_loss: Option<f64>,
    /// Bandwidth in bytes/sec. Default 250.
    pub bandwidth_bps: Option<f64>,
    /// Base latency in ms. Default 5000.
    pub base_latency_ms: Option<f64>,
}

#[derive(Debug, Default)]
pub struct LoraSimResult {
    pub delivered: Vec<Packet>,
    pub dropped: Vec<Packet>,
    /// Cumulative simulated latency, ms.
    pub total_latency_ms: f64,
}

/// Walk a list of packets through a one-way LoRa-style channel. Drops
/// packets per `packet_loss`, accumulates latency proportional to size /
/// `bandwidth_bps`. Pure simulation — no IO. The optional `rng_seed`
/// argument makes the result deterministic for tests.
pub fn simulate_lora(
    packets: &[Packet],
    opts: LoraSimOptions,
    rng_seed: Option<u64>,
) -> LoraSimResult {
    let loss = opts.packet_loss.unwrap_or(0.0);
    let bw = opts.bandwidth_bps.unwrap_or(250.0);
    let base = opts.base_latency_ms.unwrap_or(5000.0);
    let mut state = rng_seed.unwrap_or(0xdeadbeef_dead_beefu64);
    let mut next = move || {
        // xorshift64* — small deterministic PRNG, values in (0,1).
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;

        (state.wrapping_mul(0x2545_F491_4F6C_DD1Du64) >> 11) as f64 / (1u64 << 53) as f64
    };
    let mut delivered = Vec::with_capacity(packets.len());
    let mut dropped: Vec<Packet> = Vec::new();
    let mut total_latency_ms = 0.0_f64;
    for p in packets {
        let canonical = serde_json::to_string(p).unwrap_or_default();
        let size_bytes = canonical.len() as f64;
        let tx_ms = (size_bytes / bw) * 1000.0;
        total_latency_ms += base + tx_ms;
        if next() < loss {
            dropped.push(p.clone());
        } else {
            delivered.push(p.clone());
        }
    }
    LoraSimResult {
        delivered,
        dropped,
        total_latency_ms,
    }
}

#[cfg(test)]
mod lora_tests {
    use super::*;
    use rand::rngs::OsRng;

    fn fixture(packet_id: &str) -> Packet {
        let signer = "tf:actor:agent:example.com/x";
        let mut signer_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut signer_seed);
        sign_packet(SignPacketArgs {
            packet_id: packet_id.into(),
            source: signer.into(),
            destination: "tf:actor:service:example.com/d".into(),
            priority: "P3".into(),
            payload: b"hi",
            encoding: None,
            compression: None,
            emergency: false,
            expires_at: None,
            ttl_hops: None,
            route_constraints: None,
            session_ref: None,
            private_key: signer_seed,
            signer: signer.into(),
            created_at: Some("2026-04-24T12:00:00Z".into()),
        })
        .expect("sign")
    }

    #[test]
    fn lossless_channel_delivers_everything() {
        let packets = vec![fixture("a"), fixture("b"), fixture("c")];
        let r = simulate_lora(
            &packets,
            LoraSimOptions {
                packet_loss: Some(0.0),
                bandwidth_bps: Some(250.0),
                base_latency_ms: Some(5000.0),
            },
            Some(1),
        );
        assert_eq!(r.delivered.len(), 3);
        assert_eq!(r.dropped.len(), 0);
        assert!(r.total_latency_ms > 15_000.0);
    }

    #[test]
    fn full_loss_drops_everything() {
        let packets = vec![fixture("a"), fixture("b")];
        let r = simulate_lora(
            &packets,
            LoraSimOptions {
                packet_loss: Some(1.0),
                ..Default::default()
            },
            Some(42),
        );
        assert_eq!(r.delivered.len(), 0);
        assert_eq!(r.dropped.len(), 2);
    }

    #[test]
    fn deterministic_with_seed() {
        let packets: Vec<Packet> = (0..10).map(|i| fixture(&format!("pkt-{}", i))).collect();
        let r1 = simulate_lora(
            &packets,
            LoraSimOptions {
                packet_loss: Some(0.5),
                ..Default::default()
            },
            Some(99),
        );
        let r2 = simulate_lora(
            &packets,
            LoraSimOptions {
                packet_loss: Some(0.5),
                ..Default::default()
            },
            Some(99),
        );
        assert_eq!(r1.delivered.len(), r2.delivered.len());
        assert_eq!(r1.dropped.len(), r2.dropped.len());
    }
}
