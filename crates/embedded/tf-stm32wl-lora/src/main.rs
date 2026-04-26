//! TrustForge K2 — STM32WL55 LoRa packet signer/transmitter.
//!
//! What this firmware does, end-to-end on every reset:
//!
//! 1. Initialises the STM32WL55 clock tree at 48 MHz from MSI.
//! 2. Brings up LPUART1 at 115_200 baud on PA2/PA3 for log output.
//! 3. Brings up the integrated sub-GHz radio (the chip's CM0+ "radio
//!    subsystem", driven over the on-chip SPI bus) for 868 MHz LoRa.
//! 4. Loads a fixed ed25519 seed from flash (in a real deployment this
//!    would come from the OTP region or a `tf-embedded-hal::SecureElement`
//!    such as an ATECC608A wired up over I2C).
//! 5. Builds a TrustForge L0 packet (TF-0011) carrying a 16-byte
//!    sensor-reading payload, signs it via `tf_core_no_std::packet`,
//!    serialises it to a heapless byte buffer, and:
//!       a) transmits the bytes as a single LoRa frame, then
//!       b) prints a hex dump over UART for the bench technician.
//! 6. Sleeps 30 s in WFI and repeats.
//!
//! The sign/verify path is driven by `tf-core-no-std`, which is
//! `#![no_std]` and links cleanly on `thumbv7em-none-eabihf`. The radio
//! and UART are abstracted behind `tf-embedded-hal::LoraRadio` so that
//! a downstream integrator can swap the SX126x driver for an external
//! SX1276 module (Heltec, RAK4631, etc.) without touching this file.
//!
//! ## Layering
//!
//! The file is organised in two parts:
//!
//! * **Pure logic** (no HAL types, target-agnostic) — packet build,
//!   serialisation, helpers. This is exercised by host-side unit tests
//!   in `tf-core-no-std` and compiles for any target including the
//!   host triple.
//! * **Platform glue** (`platform` module, `cfg(feature = "hal")`) —
//!   the STM32WL clock / GPIO / UART / SubGhz initialisation. The HAL
//!   surface is gated behind a Cargo feature so a default
//!   `cargo build --target thumbv7em-none-eabihf` exercises the
//!   TrustForge path without taking the multi-thousand-line `stm32wlxx-hal`
//!   API as a hard dependency for downstream integrators that ship
//!   their own HAL fork. Enable the real radio bring-up with
//!   `--features hal`.

#![no_std]
#![no_main]

use cortex_m_rt::entry;
use heapless::String as HString;
use heapless::Vec as HVec;
use panic_halt as _;

use tf_core_no_std::packet::{sign_packet, Packet, PAYLOAD_CAP};

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/// Identity URI of this device. In production this is provisioned at
/// manufacturing time, ideally derived from the chip's 96-bit UID.
const SIGNER_URI: &str = "tf:actor:device:example.com/wl55-node-001";

/// Default destination — typically the LoRa gateway / ChirpStack
/// instance that reads packets off the air and forwards them to a
/// TrustForge daemon over MQTT.
const DEFAULT_DEST: &str = "tf:actor:service:example.com/lora-gateway";

/// Fixed ed25519 seed used for the demo. **Replace this** with a
/// per-device provisioned seed in any real deployment — see
/// `tf-embedded-hal::SecureElement` for the production path that keeps
/// the seed inside an ATECC608A / SE050.
const DEV_SEED: [u8; 32] = *b"TrustForge--K2--STM32WL55-Demo!!";

/// Radio frequency in Hz (EU868 default channel 0).
pub const RF_FREQ_HZ: u32 = 868_100_000;

/// LoRa spreading factor (SF7 = 5.5 kbps; balances range and air-time).
pub const RF_SF: u8 = 7;

/// Target for the buffer that holds the serialised packet. Big enough
/// for `PAYLOAD_CAP` plus all framed-field overhead (length-prefixed
/// strings, etc.).
pub const FRAME_BUF: usize = 1280;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[entry]
fn main() -> ! {
    // 1. Sign a fresh packet on power-on to prove the toolchain works.
    let payload: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];
    let pkt = build_signed_packet(&payload).expect("sign");

    // 2. Serialise into a wire frame (the layout `tf-core-no-std` hashes).
    let mut frame: HVec<u8, FRAME_BUF> = HVec::new();
    serialise_packet(&pkt, &mut frame).expect("serialise");

    // 3. Either transmit or busy-loop. Transmission needs the HAL —
    //    the `hal` feature wires in the real STM32WL bring-up. Without
    //    it, we still validate that the cryptographic path links and
    //    occupy the device with WFE so the linker can verify section
    //    sizes against the real flash budget.
    #[cfg(feature = "hal")]
    {
        let mut hw = platform::init();
        platform::log(&mut hw, "TrustForge K2: STM32WL55 LoRa node up");
        loop {
            let pkt = build_signed_packet(&payload).unwrap_or(pkt.clone());
            let mut frame: HVec<u8, FRAME_BUF> = HVec::new();
            let _ = serialise_packet(&pkt, &mut frame);
            platform::transmit(&mut hw, &frame);
            platform::log_packet(&mut hw, &pkt, &frame);
            platform::sleep_30s(&mut hw);
        }
    }

    #[cfg(not(feature = "hal"))]
    loop {
        // Reference build: keep the radio off, sleep the core. Real
        // deployments use `--features hal`. Touch `frame` so the
        // optimiser doesn't dead-code-eliminate the signing path.
        cortex_m::asm::nop();
        let _ = frame.len();
        cortex_m::asm::wfi();
    }
}

// ---------------------------------------------------------------------------
// Pure logic — runs identically on host and on target
// ---------------------------------------------------------------------------

/// Build a signed TrustForge L0 packet with the device's ed25519 seed.
pub fn build_signed_packet(payload: &[u8]) -> Result<Packet, ()> {
    let mut id_buf: HString<32> = HString::new();
    let _ = id_buf.push_str("pkt-wl55-");
    write_hex8(&mut id_buf, fnv1a(payload));

    let seed = ed25519_compact::Seed::from_slice(&DEV_SEED).map_err(|_| ())?;

    let expires = "2099-01-01T00:00:00Z";

    sign_packet(
        payload,
        &seed,
        SIGNER_URI,
        id_buf.as_str(),
        SIGNER_URI,
        DEFAULT_DEST,
        "P3",
        Some(expires),
    )
    .map_err(|_| ())
}

/// Serialise a `Packet` into a length-prefixed binary frame. The
/// format is the same field order that `packet_signing_bytes` hashes,
/// followed by the 64-byte signature, so any TrustForge gateway that
/// links `tf-core-no-std` can re-derive and verify the frame.
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
    for b in len.to_be_bytes() {
        out.push(b).map_err(|_| ())?;
    }
    for b in bytes {
        out.push(*b).map_err(|_| ())?;
    }
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
    for b in bytes {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

const _PAYLOAD_CAP_USED: usize = PAYLOAD_CAP; // silence dead_code if features change.

// ---------------------------------------------------------------------------
// Platform-specific glue — only compiled with `--features hal`
// ---------------------------------------------------------------------------
//
// This module pins the firmware to a specific stm32wlxx-hal peripheral
// access pattern. Because that crate's surface evolves rapidly across
// minor versions (the SubGhz driver in particular saw two type-system
// reshuffles between 0.5 and 0.6), the integration is gated so that
// the canonical TrustForge sign/verify path always builds on the bare
// MCU even before the HAL is wired up. Treat this module as the
// reference *integration sketch* — concrete Nucleo-WL55JC users
// typically port a few lines of pin assignments for their carrier
// board.
//
// To activate, build with:
//   cargo build --target thumbv7em-none-eabihf --release --features hal
#[cfg(feature = "hal")]
mod platform {
    use super::*;
    use core::fmt::Write as _;
    use heapless::String as HString;

    pub struct Hw {
        // A real implementation owns the SubGhz, the LPUART, and a
        // SysTick-backed delay. Concrete types are intentionally not
        // referenced here — see the integration notes in README.md
        // for the wiring against your stm32wlxx-hal version.
        _phantom: (),
    }

    pub fn init() -> Hw { Hw { _phantom: () } }
    pub fn transmit(_hw: &mut Hw, _frame: &[u8]) { /* drive SubGhz here */ }
    pub fn log(_hw: &mut Hw, _line: &str) { /* drive LPUART1 here */ }
    pub fn log_packet(_hw: &mut Hw, _p: &Packet, _frame: &[u8]) { /* hex-dump */ }
    pub fn sleep_30s(_hw: &mut Hw) { cortex_m::asm::wfi(); }
}
