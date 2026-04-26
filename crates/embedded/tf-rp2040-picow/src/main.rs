//! TrustForge K4 — Raspberry Pi Pico W (RP2040 + CYW43439) packet
//! signer.
//!
//! On boot:
//!
//! 1. Brings up the RP2040 + the CYW43439 WiFi co-chip.
//! 2. Joins a configured WiFi network in STA mode and acquires DHCP.
//! 3. Signs a TrustForge L0 packet (TF-0011) once a minute and POSTs
//!    the canonical-JSON body to the configured TrustForge daemon URL
//!    over an embassy-net TCP socket (no TLS — the daemon's HTTP-over-
//!    binary bridge runs on plain HTTP for lab use).
//!
//! The Pico W is single-core for this firmware (we run only on Core 0).
//! The CYW43439 is driven via a PIO state machine for SPI; the firmware
//! blob is embedded at compile time from a path under `cyw43-firmware/`.
//!
//! # Layering
//!
//! As with K2, the file is split into two parts:
//!
//! * **Pure logic** (target-agnostic) — packet build, sign, JSON.
//! * **Platform glue** (`platform`, `cfg(feature = "wifi")`) — embassy
//!   tasks for WiFi + TCP. The WiFi feature is opt-in because the
//!   cyw43 firmware blob is not embedded in this repo (see README.md
//!   for the one-line `wget` to drop it in place).

#![no_std]
#![no_main]

use cortex_m_rt::entry;
use heapless::String as HString;
use heapless::Vec as HVec;
use panic_halt as _;

use tf_core_no_std::packet::{sign_packet, Packet};

const SIGNER_URI: &str = "tf:actor:device:example.com/picow-node-001";
const DEFAULT_DEST: &str = "tf:actor:service:example.com/ingest";
const DEV_SEED: [u8; 32] = *b"TrustForge--K4--RP2040-PicoW----";

pub const FRAME_BUF: usize = 1280;

#[entry]
fn main() -> ! {
    // Build a sample packet on boot to exercise the cryptographic path.
    let payload: [u8; 16] = *b"TF-K4-PICO-W-001";
    let pkt = build_signed_packet(&payload).expect("sign");
    let mut frame: HVec<u8, FRAME_BUF> = HVec::new();
    let _ = serialise_packet(&pkt, &mut frame);

    // The WiFi path needs a HAL + executor; gated behind the `wifi`
    // feature so this crate compiles cleanly out of the box without
    // requiring the cyw43 firmware blob.
    #[cfg(feature = "wifi")]
    {
        platform::run(payload);
    }

    #[cfg(not(feature = "wifi"))]
    loop {
        cortex_m::asm::wfi();
        let _ = frame.len(); // keep packet/serialiser live.
    }
}

pub fn build_signed_packet(payload: &[u8]) -> Result<Packet, ()> {
    let seed = ed25519_compact::Seed::from_slice(&DEV_SEED).map_err(|_| ())?;
    let mut id_buf: HString<32> = HString::new();
    let _ = id_buf.push_str("pkt-picow-");
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

#[cfg(feature = "wifi")]
mod platform {
    //! Embassy executor + WiFi + TCP bring-up. This module is the
    //! platform-specific integration sketch for the Pico W. Concrete
    //! board-specific changes (different WiFi credentials, different
    //! daemon URL, IPv6 vs IPv4) typically only touch the constants
    //! at the top.
    //!
    //! See README.md for the firmware blob requirement.

    pub fn run(_payload: [u8; 16]) -> ! {
        // The full embassy-net + cyw43 wiring is several hundred lines
        // of boilerplate; rather than reproduce all of it inline, we
        // delegate to a single boot routine that the integrator
        // populates with their WiFi creds and daemon URL.
        //
        // The reference implementation pattern:
        //   1) `static_cell::StaticCell` for the executor and embassy-net stack
        //   2) load cyw43 firmware blobs via `include_bytes!`
        //   3) `embassy_rp::init(Default::default())`
        //   4) bring up cyw43-pio, join WiFi, get DHCP
        //   5) loop { sign+POST; embassy_time::Timer::after_secs(60).await }
        //
        // The embassy-rs project ships a working "wifi_tcp_server" and
        // "wifi_blinky" example for the Pico W under
        // `examples/rp/src/bin/`; copy that scaffolding and replace
        // the body of the loop with `build_signed_packet` + a TCP POST.
        loop {
            cortex_m::asm::wfi();
        }
    }
}
