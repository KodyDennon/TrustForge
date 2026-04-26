# tf-rp2040-picow — TrustForge K4

Reference firmware for the **Raspberry Pi Pico W** (RP2040 Cortex-M0+
+ Infineon CYW43439 WiFi) that demonstrates the TrustForge packet-mode
flow over WiFi.

On boot:

1. The RP2040 brings up its PIO-driven SPI link to the CYW43439.
2. The cyw43 driver loads its firmware blob and joins a configured
   WiFi access point in STA mode.
3. embassy-net acquires a DHCP lease.
4. Every 60 s the firmware:
       - builds a TrustForge L0 packet (TF-0011),
       - signs it via `tf-core-no-std::packet::sign_packet` (ed25519),
       - opens a TCP socket to the configured TrustForge daemon URL
         and POSTs the canonical-JSON body.

## Hardware

| Item            | Value                                      |
| --------------- | ------------------------------------------ |
| Chip            | RP2040 (dual-core Cortex-M0+ @ 133 MHz)    |
| WiFi co-chip    | Infineon CYW43439 (b/g/n on 2.4 GHz)       |
| Flash / RAM     | 2 MiB QSPI / 264 KiB SRAM                  |
| Target triple   | `thumbv6m-none-eabi`                       |
| Reference board | Raspberry Pi Pico W (rev 1.0 or later)     |

## Build

```sh
rustup target add thumbv6m-none-eabi

# Default build — exercises the sign/serialise path without enabling
# the cyw43 firmware-blob dependency.
cargo build --target thumbv6m-none-eabi --release

# Full WiFi build:
#   1. Drop the cyw43 firmware blob into ./cyw43-firmware/
#      (see https://github.com/embassy-rs/embassy/tree/main/cyw43-firmware
#       — `43439A0.bin` and `43439A0_clm.bin`).
#   2. Build with the wifi feature.
cargo build --target thumbv6m-none-eabi --release --features wifi
```

## Flash

```sh
cargo install probe-rs --features cli
cargo run --target thumbv6m-none-eabi --release --features wifi
```

The runner is `probe-rs run --chip RP2040`. Plug in a CMSIS-DAP
compatible debugger (e.g. a second Pico flashed with picoprobe) — the
Pico W's BOOTSEL button + USB-mass-storage path also works for
manual UF2 deployment via `elf2uf2-rs`.

## Configuration

Edit the constants near the top of `src/main.rs`:

```rust
const SIGNER_URI:   &str = "tf:actor:device:example.com/picow-node-001";
const DEFAULT_DEST: &str = "tf:actor:service:example.com/ingest";
const DEV_SEED:     [u8; 32] = *b"TrustForge--K4--RP2040-PicoW----";
```

The `wifi` module's `run` routine is the integration sketch — set
WiFi creds and daemon URL there. For production, store these in the
last 4 KiB of flash (`embassy-rp::flash::Flash`) and read at boot.

## Identity & key handling

The same caveats as K2 apply: the baked-in seed is a placeholder.
Production deployments either provision a per-device seed in flash
during manufacturing or attach an external secure element via I2C and
implement `tf-embedded-hal::SecureElement`.

## Status

Compiles for `thumbv6m-none-eabi` out of the box (default features).
The `wifi` feature requires the cyw43 firmware blob — see the embassy
repository for the redistributable firmware files. The TrustForge
sign/verify path is target-agnostic and fully exercised by the
`tf-core-no-std` host-side test suite.
