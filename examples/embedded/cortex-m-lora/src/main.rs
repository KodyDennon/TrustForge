//! TrustForge Cortex-M LoRa node — STM32WL55JC reference example.
//!
//! Demonstrates the embedded packet-mode flow (TF-0011):
//!
//!   1. SubGHz LoRa radio is initialized via embassy-stm32.
//!   2. The device derives an ed25519 keypair from a deterministic seed.
//!      In production, the seed (or the key itself) lives in a secure
//!      element and is fronted by `tf_embedded_hal::SecureElement`.
//!   3. Main loop: receive a LoRa frame -> deserialize into a
//!      `tf_core_no_std::packet::Packet` -> consult the cached ORL
//!      (`OfflineRevocationListChecker`) -> consult the replay-protected
//!      `PacketReceiver` -> verify the signature -> if all checks pass,
//!      enqueue a signed proof packet on the TX queue.
//!
//! This is a *reference example*: the LoRa wire framing is left abstract
//! (the on-air encoding is decided by the deployment) and the radio
//! driver is wired through `tf_embedded_hal::LoraRadio` so the same
//! example body works against the SX126x family or a SubGHz peripheral.

#![no_std]
#![no_main]

use defmt::{info, warn};
use defmt_rtt as _;
use panic_probe as _;

use embassy_executor::Spawner;
use embassy_stm32::Config as StmConfig;
use embassy_time::{Duration, Timer};

use heapless::Vec as HVec;

use tf_core_no_std::{
    nonce_cache::{PacketReceiver, ReceiverDecision},
    orl::{OfflineRevocationListChecker, RevokedKind},
    packet::{sign_packet, verify_packet, Packet, PAYLOAD_CAP, SIGNATURE_CAP, STRING_CAP},
    PublicKeyBytes, SecretSeedBytes,
};
use tf_embedded_hal::{Entropy, LoraRadio, SecureElement};

use ed25519_compact::{KeyPair, Seed};

/// Maximum LoRa frame we are willing to buffer — sized to accommodate a
/// SF7@250kHz payload plus headroom.
const MAX_LORA_FRAME: usize = 256;

/// The actor URI of *this* device. In production this is provisioned at
/// manufacturing time and pinned in the secure element.
const SELF_ACTOR: &str = "tf:actor:agent:example.com/lora-node-1";
/// Where signed proof packets are forwarded.
const PROOF_DESTINATION: &str = "tf:actor:service:example.com/proof-aggregator";

/// Expected issuer of the ORL we will trust (pinned at manufacturing).
const ORL_ISSUER_PUB: PublicKeyBytes = [0u8; 32];

/// Embedded ORL bytes — populated from the latest signed snapshot we
/// trust. In a production build this is patched into a known flash
/// region and updated by the gateway over LoRa periodically.
static ORL_BYTES: &[u8] = &[];

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let _ = spawner;
    let stm_config = StmConfig::default();
    let _p = embassy_stm32::init(stm_config);

    info!("tf-cortex-m-lora-example: booted");

    // 1. Initialize the LoRa radio. `tf_embedded_hal::LoraRadio` is the
    //    portable abstraction; the concrete SubGHz binding is selected
    //    by the HAL build.
    let mut radio = match tf_embedded_hal::lora_subghz_init() {
        Ok(r) => r,
        Err(_) => {
            defmt::error!("failed to bring up LoRa SubGHz radio");
            loop {
                Timer::after(Duration::from_secs(5)).await;
            }
        }
    };

    // 2. Derive the ed25519 keypair from the secure element. For this
    //    reference example we fall back to a deterministic seed so the
    //    flow is reproducible on the bench.
    let seed_bytes: SecretSeedBytes = match tf_embedded_hal::secure_element_export_seed() {
        Ok(b) => b,
        Err(_) => {
            warn!("no secure element; using deterministic test seed");
            [0xA5u8; 32]
        }
    };
    let seed = Seed::from_slice(&seed_bytes).expect("seed is 32 bytes");
    let kp = KeyPair::from_seed(seed);
    let our_pub: PublicKeyBytes = (*kp.pk).into();
    info!("device public key bound; entering RX loop");

    // 3. Boot the ORL and the replay cache.
    let orl = OfflineRevocationListChecker::new(
        ORL_BYTES,
        &ORL_ISSUER_PUB,
        "2026-04-25T00:00:00Z",
    )
    .ok();
    let mut nonce_cache: PacketReceiver<64> = PacketReceiver::new();

    // 4. Steady-state RX/TX loop.
    loop {
        let mut frame: HVec<u8, MAX_LORA_FRAME> = HVec::new();
        match radio.recv(&mut frame).await {
            Ok(()) => {}
            Err(_) => {
                Timer::after(Duration::from_millis(50)).await;
                continue;
            }
        }

        // Decode the frame into a Packet. The wire layout is the
        // concatenated TF-0011 packet fields produced by `sign_packet`.
        let packet = match decode_frame(&frame) {
            Some(p) => p,
            None => {
                warn!("dropped malformed frame ({} bytes)", frame.len());
                continue;
            }
        };

        let now_str = "2026-04-25T00:00:00Z";

        // ORL gate.
        if let Some(orl) = orl.as_ref() {
            if orl.is_revoked(RevokedKind::Actor, packet.signer.as_str()) {
                warn!("rejecting packet: signer is revoked");
                continue;
            }
        }

        // Replay gate.
        let decision = nonce_cache.observe(
            packet.packet_id.as_str(),
            packet.expires_at.as_ref().map(|s| s.as_str()),
            now_str,
        );
        if !matches!(decision, ReceiverDecision::Accept) {
            warn!("rejecting packet: nonce-cache rejected");
            continue;
        }

        // Signature gate. The verify key is delivered by the gateway
        // along with the signed packet (or pre-pinned in the device).
        // For this example we use the verifier's own key as a stand-in
        // for any peer key already known.
        if verify_packet(&packet, &our_pub, now_str).is_err() {
            warn!("rejecting packet: signature did not verify");
            continue;
        }

        info!(
            "accepted packet id={} from={}",
            packet.packet_id.as_str(),
            packet.signer.as_str(),
        );

        // 5. Forward a signed proof-of-receipt back out on the TX queue.
        let proof = match sign_packet(
            packet.packet_id.as_bytes(),
            &seed,
            SELF_ACTOR,
            packet.packet_id.as_str(),
            SELF_ACTOR,
            PROOF_DESTINATION,
            "P3",
            None,
        ) {
            Ok(p) => p,
            Err(_) => {
                warn!("failed to sign proof packet");
                continue;
            }
        };
        let mut tx_buf: HVec<u8, MAX_LORA_FRAME> = HVec::new();
        if encode_frame(&proof, &mut tx_buf).is_err() {
            warn!("proof packet exceeds LoRa frame budget");
            continue;
        }
        if radio.send(&tx_buf).await.is_err() {
            warn!("failed to enqueue proof packet on TX");
        }

        Timer::after(Duration::from_millis(10)).await;
    }
}

/// Encode a `Packet` into a flat byte buffer suitable for the LoRa air
/// interface. Layout mirrors the field order used by
/// `tf_core_no_std::packet::packet_signing_bytes` plus the trailing
/// signature.
fn encode_frame(p: &Packet, out: &mut HVec<u8, MAX_LORA_FRAME>) -> Result<(), ()> {
    write_lp(out, p.packet_version.as_bytes())?;
    write_lp(out, p.packet_id.as_bytes())?;
    write_lp(out, p.source.as_bytes())?;
    write_lp(out, p.destination.as_bytes())?;
    write_lp(out, p.priority.as_bytes())?;
    out.push(p.emergency as u8).map_err(|_| ())?;
    write_lp(out, p.created_at.as_bytes())?;
    match p.expires_at.as_ref() {
        Some(e) => {
            out.push(1).map_err(|_| ())?;
            write_lp(out, e.as_bytes())?;
        }
        None => {
            out.push(0).map_err(|_| ())?;
        }
    }
    write_lp(out, p.signer.as_bytes())?;
    write_lp(out, p.algorithm.as_bytes())?;
    write_lp(out, p.payload.as_slice())?;
    write_lp(out, p.signature.as_slice())?;
    Ok(())
}

fn write_lp(out: &mut HVec<u8, MAX_LORA_FRAME>, data: &[u8]) -> Result<(), ()> {
    let len = data.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()).map_err(|_| ())?;
    out.extend_from_slice(data).map_err(|_| ())?;
    Ok(())
}

/// Decode a frame previously written by `encode_frame`. Returns `None`
/// on any framing error; the receiver simply drops the packet in that
/// case.
fn decode_frame(buf: &[u8]) -> Option<Packet> {
    let mut cur = Cursor { buf, pos: 0 };
    let version = cur.read_lp_into::<8>()?;
    let packet_id = cur.read_lp_into::<STRING_CAP>()?;
    let source = cur.read_lp_into::<STRING_CAP>()?;
    let destination = cur.read_lp_into::<STRING_CAP>()?;
    let priority = cur.read_lp_into::<8>()?;
    let emergency = cur.read_u8()? != 0;
    let created_at = cur.read_lp_into::<STRING_CAP>()?;
    let has_exp = cur.read_u8()? != 0;
    let expires_at = if has_exp {
        Some(cur.read_lp_into::<STRING_CAP>()?)
    } else {
        None
    };
    let signer = cur.read_lp_into::<STRING_CAP>()?;
    let algorithm = cur.read_lp_into::<16>()?;
    let payload_bytes = cur.read_lp()?;
    let signature_bytes = cur.read_lp()?;

    let mut payload: HVec<u8, PAYLOAD_CAP> = HVec::new();
    payload.extend_from_slice(payload_bytes).ok()?;
    let mut signature: HVec<u8, SIGNATURE_CAP> = HVec::new();
    signature.extend_from_slice(signature_bytes).ok()?;

    Some(Packet {
        packet_version: version,
        packet_id,
        source,
        destination,
        priority,
        emergency,
        created_at,
        expires_at,
        signer,
        algorithm,
        payload,
        signature,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(u32::from_be_bytes(bytes))
    }
    fn read_lp(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Some(out)
    }
    fn read_lp_into<const N: usize>(&mut self) -> Option<heapless::String<N>> {
        let bytes = self.read_lp()?;
        let s = core::str::from_utf8(bytes).ok()?;
        let mut out: heapless::String<N> = heapless::String::new();
        out.push_str(s).ok()?;
        Some(out)
    }
}
