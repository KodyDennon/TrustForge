# tf-avr-atmega328 — TrustForge K7

Reference firmware for the **Arduino Uno (ATmega328P)**, the canonical
"very-constrained" target: 32 KiB flash, 2 KiB SRAM, an 8-bit AVR core.

## What this firmware demonstrates

A full ed25519 signing operation (curve scalar mult + SHA-512) costs
more flash and stack than is comfortable on a 328P while leaving room
for an application. K7 therefore demonstrates the
**delegated-signing** pattern from `docs/profiles/constrained.md`:

1. The Uno builds the TrustForge L0 packet **header** (TF-0011 §3) and
   serialises it to the same length-prefixed binary frame used by K2 /
   K4 / K5 / K6, *without* the trailing signature.
2. The unsigned frame is emitted over UART at 57_600 baud as a hex
   line prefixed `TF-UNSIGNED `.
3. A host process (or, in production, an attached secure element over
   I2C — ATECC608A, SE050, OPTIGA Trust M) signs the bytes and re-injects
   the completed frame onto the wire.

This shows that TrustForge fits even on an 8-bit AVR if you offload
crypto to an SE — *the protocol surface itself has no AVR-hostile
primitives*.

## Hardware

| Item            | Value                                       |
| --------------- | ------------------------------------------- |
| Chip            | ATmega328P (8-bit AVR @ 16 MHz)             |
| Flash / SRAM    | 32 KiB / 2 KiB                              |
| Target triple   | `avr-unknown-gnu-atmega328`                 |
| Reference board | Arduino Uno R3, Sparkfun RedBoard           |
| Suggested SE    | ATECC608A (I2C, ed25519 in HW)              |

## Toolchain

AVR support is **only available on Rust nightly** and requires the
host AVR toolchain (`avr-gcc`, `avr-libc`, `avrdude`, `ravedude`):

```sh
# Nightly Rust:
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Host tools (macOS):
brew tap osx-cross/avr
brew install avr-gcc avrdude
cargo install ravedude

# Host tools (Linux Debian/Ubuntu):
sudo apt install gcc-avr avr-libc avrdude
cargo install ravedude
```

## Build

```sh
cargo +nightly build --release \
  -Z build-std=core \
  --target ./avr-specs/avr-atmega328p.json
```

The target spec is checked in at `avr-specs/avr-atmega328p.json` —
copy any vendor-specific overrides there. Newer nightlies require the
`-Z json-target-spec` flag explicitly.

## Flash

```sh
cargo +nightly run --release \
  -Z build-std=core \
  --target ./avr-specs/avr-atmega328p.json
```

The cargo runner is wired to `ravedude uno -cb 57600`, which auto-
detects the Uno's USB-serial port and invokes `avrdude` with the
right options. Open the serial monitor at the same baud to see the
`TF-UNSIGNED ...` hex lines.

## Wire format

Each line emitted on UART looks like:

```
TF-UNSIGNED 0000000131000000146e6f64652d70...0000000a3230393...
```

After hex-decoding, the bytes are the layout that `tf-core-no-std`'s
`packet_signing_bytes` hashes — fields in the same order, each with a
`u32` BE length prefix, *minus the trailing signature field*. The
relay or SE computes SHA-256 over those bytes (skipping the
signature-tail), signs with ed25519, then concatenates a 4-byte
length prefix (`0x00000040`) + the 64-byte signature and forwards the
completed frame.

## Status

Reference firmware. **Did not compile on the build host** (this
machine has neither nightly Rust set up for AVR nor `avr-gcc`
installed). The crate is structurally complete and the cargo plumbing
follows the upstream `avr-hal-template` conventions; expect a fresh
checkout to build cleanly on a host with the toolchain prerequisites
above.

See [TF-0011 packet-mode spec](../../../docs/specs/TF-0011-packet-mode-and-relays.md)
for the canonical packet semantics, and
[`docs/profiles/constrained.md`](../../../docs/profiles/constrained.md)
for the very-constrained profile that K7 targets.
