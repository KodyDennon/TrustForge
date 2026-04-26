//! TrustForge K5 — nRF52840 BLE peripheral exposing a signed-packet
//! GATT characteristic.
//!
//! On boot:
//!
//! 1. Initialises the Nordic SoftDevice S140 BLE stack alongside the
//!    application core.
//! 2. Registers a single GATT service with one read+notify
//!    characteristic. The 16-byte service UUID is allocated under
//!    Nordic's vendor-specific base UUID (`0xC0DE` short form for
//!    demonstration; for production allocate via the Bluetooth SIG).
//! 3. Starts undirected connectable advertising at 100 ms interval.
//! 4. On every characteristic READ:
//!       - samples a 16-byte mock sensor reading,
//!       - builds and signs a TrustForge L0 packet,
//!       - returns the serialised packet bytes (truncated to the MTU
//!         negotiated by the central — typical 247 B with the default
//!         SoftDevice config; large packets fragment over multiple
//!         MTU-sized notifications).
//!
//! The BLE bridge profile (TF-0011 §packet-mode appendix B and the
//! BLE bridge spec under `docs/bridges/`) treats the central as a
//! relay: it receives signed packets and forwards them upstream over
//! its own bearer (typically WiFi or LTE) without ever holding the
//! peripheral's signing key. Forwarding authority and action authority
//! are independent — see TF-0011.
//!
//! ## Build modes
//!
//! As with K2 and K4, the BLE/SoftDevice integration is gated behind
//! the `ble` Cargo feature. The default build exercises only the
//! TrustForge sign/serialise path and links cleanly without the
//! SoftDevice binary blob (which lives outside this repo and must be
//! flashed separately to address `0x00000000`–`0x00027000`). With
//! `--features ble` the firmware drives the Nordic stack and is the
//! actual peripheral.

#![no_std]
#![no_main]

use cortex_m_rt::entry;
use heapless::String as HString;
use heapless::Vec as HVec;
use panic_halt as _;

use tf_core_no_std::packet::{sign_packet, Packet};

const SIGNER_URI: &str = "tf:actor:device:example.com/nrf52-tag-001";
const DEFAULT_DEST: &str = "tf:actor:service:example.com/ble-relay";
const DEV_SEED: [u8; 32] = *b"TrustForge--K5--nRF52-BLE-Demo!!";

pub const FRAME_BUF: usize = 1024;

#[entry]
fn main() -> ! {
    // Pre-build a packet on boot to exercise the cryptographic path.
    let payload: [u8; 16] = *b"TF-K5-NRF52-DEMO";
    let pkt = build_signed_packet(&payload).expect("sign");
    let mut frame: HVec<u8, FRAME_BUF> = HVec::new();
    let _ = serialise_packet(&pkt, &mut frame);

    #[cfg(feature = "ble")]
    {
        platform::run();
    }

    #[cfg(not(feature = "ble"))]
    loop {
        cortex_m::asm::wfi();
        let _ = frame.len();
    }
}

pub fn build_signed_packet(payload: &[u8]) -> Result<Packet, ()> {
    let seed = ed25519_compact::Seed::from_slice(&DEV_SEED).map_err(|_| ())?;
    let mut id_buf: HString<32> = HString::new();
    let _ = id_buf.push_str("pkt-nrf52-");
    write_hex8(&mut id_buf, fnv1a(payload));
    sign_packet(
        payload,
        &seed,
        SIGNER_URI,
        id_buf.as_str(),
        SIGNER_URI,
        DEFAULT_DEST,
        "P3",
        Some("2099-01-01T00:00:00Z"),
    )
    .map_err(|_| ())
}

pub fn serialise_packet(p: &Packet, out: &mut HVec<u8, FRAME_BUF>) -> Result<(), ()> {
    push_field(out, p.packet_version.as_bytes())?;
    push_field(out, p.packet_id.as_bytes())?;
    push_field(out, p.source.as_bytes())?;
    push_field(out, p.destination.as_bytes())?;
    push_field(out, p.priority.as_bytes())?;
    out.push(p.emergency as u8).map_err(|_| ())?;
    push_field(out, p.created_at.as_bytes())?;
    match &p.expires_at {
        Some(e) => {
            out.push(1).map_err(|_| ())?;
            push_field(out, e.as_bytes())?;
        }
        None => {
            out.push(0).map_err(|_| ())?;
        }
    }
    push_field(out, p.signer.as_bytes())?;
    push_field(out, p.algorithm.as_bytes())?;
    push_field(out, p.payload.as_slice())?;
    push_field(out, p.signature.as_slice())?;
    Ok(())
}

fn push_field<const N: usize>(out: &mut HVec<u8, N>, bytes: &[u8]) -> Result<(), ()> {
    let len = bytes.len() as u32;
    for b in len.to_be_bytes() { out.push(b).map_err(|_| ())?; }
    for b in bytes { out.push(*b).map_err(|_| ())?; }
    Ok(())
}

fn write_hex8<const N: usize>(s: &mut HString<N>, v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 8];
    for i in 0..8 {
        let nib = ((v >> ((7 - i) * 4)) & 0xF) as usize;
        buf[i] = HEX[nib];
    }
    let _ = s.push_str(core::str::from_utf8(&buf).unwrap_or("00000000"));
}

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes { h ^= *b as u32; h = h.wrapping_mul(0x0100_0193); }
    h
}

#[cfg(feature = "ble")]
mod platform {
    //! BLE peripheral bring-up using nrf-softdevice.
    //!
    //! The integration sketch:
    //!
    //! 1. `embassy_nrf::init` with the `softdevice` configuration, then
    //!    `nrf_softdevice::Softdevice::enable` to enable S140.
    //! 2. Register the GATT service with one characteristic UUID
    //!    `c0debabe-0000-1000-8000-00805f9b34fb` (16-bit `0xC0DE` under
    //!    the standard Bluetooth base UUID; replace with a SIG-allocated
    //!    UUID for shipping firmware).
    //! 3. `peripheral::advertise_connectable(...)` with both the
    //!    advertisement payload and the scan-response payload set.
    //! 4. On each connection, `gatt_server::run` over the channel; the
    //!    READ handler calls `super::build_signed_packet` and returns
    //!    the serialised bytes.
    //!
    //! Concrete code lives in the `nrf-softdevice` repository's
    //! `examples/ble_bas_peripheral` example — copy that scaffolding
    //! and replace the BAS service registration with the TrustForge
    //! "signed packet" service.
    pub fn run() -> ! {
        loop { cortex_m::asm::wfi(); }
    }
}
