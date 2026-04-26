//! TrustForge K6 — RISC-V ESP32-C3 packet signer.
//!
//! Prints a signed TrustForge L0 packet over UART0 (the chip's USB
//! Serial-JTAG endpoint, exposed at 115_200 baud on the dev kit's
//! `usb` connector). Repeats every 30 s.
//!
//! Why a UART-only path on the C3? It's the simplest constrained-mode
//! demonstrator: no radio, no WiFi, no IP stack. The host attached to
//! the UART acts as a relay (per TF-0011 the relay is a first-class
//! actor with separate forwarding authority). The C3 firmware shows
//! that signing the packet locally is enough — the relay can't tamper
//! with the payload because the signature binds it.

#![no_std]
#![no_main]

use heapless::String as HString;
use heapless::Vec as HVec;

use tf_core_no_std::packet::{sign_packet, Packet};

const SIGNER_URI: &str = "tf:actor:device:example.com/c3-node-001";
const DEFAULT_DEST: &str = "tf:actor:service:example.com/uart-relay";
const DEV_SEED: [u8; 32] = *b"TrustForge--K6--ESP32C3-RV-Demo!";

pub const FRAME_BUF: usize = 1280;

#[cfg(feature = "hal")]
use esp_backtrace as _;

#[cfg(not(feature = "hal"))]
use panic_halt as _;

#[cfg(feature = "hal")]
#[esp_hal::main]
fn main() -> ! {
    use core::fmt::Write;
    use esp_hal::{
        clock::ClockControl,
        delay::Delay,
        peripherals::Peripherals,
        prelude::*,
        system::SystemControl,
        uart::Uart,
    };

    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();
    let delay = Delay::new(&clocks);

    // UART0 is the USB Serial-JTAG bridge on the C3; default pins are
    // GPIO20 (TX) and GPIO21 (RX) but the USB-CDC path is auto-routed
    // when the USB interface is connected.
    let mut uart = Uart::new(peripherals.UART0, &clocks).unwrap();

    esp_println::println!("TrustForge K6: ESP32-C3 RISC-V signer up");

    let payload = *b"TF-K6-ESP32C3-AB";
    let seed = ed25519_compact::Seed::from_slice(&DEV_SEED).unwrap();

    let mut counter: u32 = 0;
    loop {
        counter = counter.wrapping_add(1);
        let mut id_buf: HString<32> = HString::new();
        let _ = id_buf.push_str("pkt-c3-");
        write_hex8(&mut id_buf, counter);

        match sign_packet(
            &payload,
            &seed,
            SIGNER_URI,
            id_buf.as_str(),
            SIGNER_URI,
            DEFAULT_DEST,
            "P3",
            Some("2099-01-01T00:00:00Z"),
        ) {
            Ok(pkt) => {
                let mut frame: HVec<u8, FRAME_BUF> = HVec::new();
                let _ = serialise_packet(&pkt, &mut frame);
                esp_println::println!(
                    "tx pkt id={} bytes={} sig0={:02x}{:02x}",
                    pkt.packet_id.as_str(),
                    frame.len(),
                    pkt.signature[0], pkt.signature[1]
                );
                // Hex-dump the framed bytes — a relay process listens
                // on the host side and forwards to the daemon.
                let _ = write!(uart, "TF-FRAME ");
                for b in frame.iter() {
                    let _ = write!(uart, "{:02x}", b);
                }
                let _ = writeln!(uart, "");
            }
            Err(e) => esp_println::println!("sign error: {:?}", e),
        }
        delay.delay_millis(30_000u32);
    }
}

#[cfg(not(feature = "hal"))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Entry point for builds without `--features hal`. We sign one
    // packet on boot so the linker keeps the cryptographic path live,
    // then halt the core. This proves the canonical TrustForge logic
    // links cleanly on `riscv32imc-unknown-none-elf` without taking a
    // hard dependency on the esp-hal stack.
    let payload = *b"TF-K6-ESP32C3-AB";
    let seed = ed25519_compact::Seed::from_slice(&DEV_SEED).unwrap();
    let pkt = sign_packet(
        &payload,
        &seed,
        SIGNER_URI,
        "pkt-c3-boot",
        SIGNER_URI,
        DEFAULT_DEST,
        "P3",
        Some("2099-01-01T00:00:00Z"),
    )
    .unwrap();
    let mut frame: HVec<u8, FRAME_BUF> = HVec::new();
    let _ = serialise_packet(&pkt, &mut frame);
    let _ = core::hint::black_box(&frame);
    loop {
        riscv::asm::wfi();
    }
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
        None => { out.push(0).map_err(|_| ())?; }
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

#[allow(dead_code)]
fn write_hex8<const N: usize>(s: &mut HString<N>, v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 8];
    for i in 0..8 {
        let nib = ((v >> ((7 - i) * 4)) & 0xF) as usize;
        buf[i] = HEX[nib];
    }
    let _ = s.push_str(core::str::from_utf8(&buf).unwrap_or("00000000"));
}
