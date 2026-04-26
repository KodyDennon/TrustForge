//! TrustForge K7 — ATmega328P (Arduino Uno) packet builder.
//!
//! The Uno is the canonical "very-constrained" target: 32 KiB flash,
//! 2 KiB SRAM, an 8-bit AVR core. A full ed25519 signing operation
//! (the curve scalar mult + SHA-512 used internally by `sign_packet`)
//! costs more flash and stack than we want to give up on this part —
//! ed25519-compact alone is ~24 KiB of code on AVR — so K7 demonstrates
//! a different point on the spectrum:
//!
//! * The Uno builds a TrustForge L0 packet **header** (TF-0011 §3) and
//!   serialises it to the same length-prefixed binary frame used by
//!   K2 / K4 / K5 / K6.
//! * The 64-byte signature slot is filled by an attached **external
//!   secure element** (ATECC608A, SE050, OPTIGA Trust M) over I2C —
//!   the SE does the curve op; the Uno just shifts bytes around. This
//!   maps exactly to `tf-embedded-hal::SecureElement::sign(msg)`.
//! * For this reference firmware we emit the unsigned header bytes
//!   over UART; a host process picks them up, asks the SE to sign,
//!   and re-injects the completed frame. This is the
//!   "very-constrained delegate-signing" pattern in
//!   `docs/profiles/constrained.md`.
//!
//! The point of K7 is to show that TrustForge fits even on an 8-bit
//! AVR if you offload crypto to an SE — *the protocol surface itself
//! has no AVR-hostile primitives*.

#![no_std]
#![no_main]

use arduino_hal::prelude::*;
use heapless::Vec as HVec;
use panic_halt as _;

const SIGNER_URI: &str = "tf:actor:device:example.com/uno-001";
const DEFAULT_DEST: &str = "tf:actor:service:example.com/uart-relay";

/// Header buffer cap. AVR has 2 KiB of SRAM total; we keep the buffer
/// small. The wire frame for a typical L0 packet with short URIs and
/// a 16-byte payload lands around 250 bytes including the eventual
/// signature.
const HEADER_BUF: usize = 256;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    ufmt::uwriteln!(&mut serial, "TrustForge K7: ATmega328P packet builder up").void_unwrap();

    let payload: [u8; 16] = *b"TF-K7-AVR-DEMO!!";
    let mut counter: u16 = 0;

    loop {
        counter = counter.wrapping_add(1);
        let mut header: HVec<u8, HEADER_BUF> = HVec::new();
        let mut id_buf = [0u8; 16];
        // Build a short hex packet ID from the counter.
        write_pkt_id(&mut id_buf, counter);
        let id_str = core::str::from_utf8(&id_buf[..15]).unwrap_or("pkt-uno-0000000");

        if build_unsigned_frame(&mut header, &payload, id_str).is_ok() {
            ufmt::uwrite!(&mut serial, "TF-UNSIGNED ").void_unwrap();
            for b in header.iter() {
                ufmt::uwrite!(&mut serial, "{:02x}", b).void_unwrap();
            }
            ufmt::uwriteln!(&mut serial, "").void_unwrap();
        } else {
            ufmt::uwriteln!(&mut serial, "TF-OVERFLOW").void_unwrap();
        }

        arduino_hal::delay_ms(30_000);
    }
}

/// Build a TrustForge L0 frame **without** the trailing signature. The
/// host (or attached SE) supplies the 64-byte signature later. This
/// matches the field order `tf-core-no-std::packet::packet_signing_bytes`
/// hashes, so the SE can compute SHA-256 over the bytes after the
/// `algorithm` field and produce a wire-format-compatible signature.
fn build_unsigned_frame(
    out: &mut HVec<u8, HEADER_BUF>,
    payload: &[u8],
    packet_id: &str,
) -> Result<(), ()> {
    push_field(out, b"1")?;                                   // version
    push_field(out, packet_id.as_bytes())?;                   // packet_id
    push_field(out, SIGNER_URI.as_bytes())?;                  // source
    push_field(out, DEFAULT_DEST.as_bytes())?;                // destination
    push_field(out, b"P3")?;                                  // priority
    out.push(0).map_err(|_| ())?;                             // emergency = false
    push_field(out, b"")?;                                    // created_at
    out.push(1).map_err(|_| ())?;                             // expires_at present
    push_field(out, b"2099-01-01T00:00:00Z")?;                // expires_at
    push_field(out, SIGNER_URI.as_bytes())?;                  // signer
    push_field(out, b"ed25519")?;                             // algorithm
    push_field(out, payload)?;                                // payload
    Ok(())
}

fn push_field(out: &mut HVec<u8, HEADER_BUF>, bytes: &[u8]) -> Result<(), ()> {
    let len = bytes.len() as u32;
    for b in len.to_be_bytes() { out.push(b).map_err(|_| ())?; }
    for b in bytes { out.push(*b).map_err(|_| ())?; }
    Ok(())
}

fn write_pkt_id(out: &mut [u8; 16], counter: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let prefix = b"pkt-uno-";
    for (i, b) in prefix.iter().enumerate() {
        out[i] = *b;
    }
    // 4 hex chars
    out[8] = HEX[((counter >> 12) & 0xF) as usize];
    out[9] = HEX[((counter >> 8) & 0xF) as usize];
    out[10] = HEX[((counter >> 4) & 0xF) as usize];
    out[11] = HEX[(counter & 0xF) as usize];
    out[12] = b'-';
    out[13] = b'0';
    out[14] = b'1';
    out[15] = 0;
}
