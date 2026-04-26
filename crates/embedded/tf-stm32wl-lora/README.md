# tf-stm32wl-lora — TrustForge K2

Reference firmware for the **STM32WL55** (Cortex-M4F + integrated
sub-GHz radio) that demonstrates the TrustForge packet-mode (TF-0011)
flow on a constrained LoRa node:

1. Build a TrustForge L0 packet (16-byte sensor reading payload).
2. Sign it with an ed25519 seed using `tf-core-no-std::packet::sign_packet`.
3. Serialise to a length-prefixed binary frame (the same field layout
   the verifier hashes — gateway-side `tf-core-no-std` re-derives and
   verifies it byte-for-byte).
4. Transmit the frame as a single LoRa packet at 868 MHz, SF7, BW125,
   CR4/5.
5. Hex-dump the frame over LPUART1 (PA2/PA3) at 115 200 baud.
6. Sleep 30 s and repeat.

## Hardware

| Item              | Value                                      |
| ----------------- | ------------------------------------------ |
| Chip              | STM32WLE5JC (single-core CM4 + radio)      |
| Flash / RAM       | 256 KiB / 64 KiB                           |
| Target triple     | `thumbv7em-none-eabihf`                    |
| Reference board   | NUCLEO-WL55JC (also Seeed LoRa-E5, RAK3172)|
| RF profile        | EU868 ch 0, +14 dBm, SF7BW125              |

## Build

```sh
# Install the Cortex-M4F target if you haven't already.
rustup target add thumbv7em-none-eabihf

# Release build (size-optimised).
cargo build --target thumbv7em-none-eabihf --release

# Inspect the ELF.
arm-none-eabi-size target/thumbv7em-none-eabihf/release/tf-stm32wl-lora
```

The release ELF should land around 60–90 KiB depending on toolchain
version, well under the 256 KiB flash budget.

## Flash

```sh
cargo install probe-rs --features cli   # one-time, host-side
cargo run --target thumbv7em-none-eabihf --release
```

The cargo runner is wired to `probe-rs run --chip STM32WLE5JCIx` — see
`.cargo/config.toml`. A connected ST-Link/V2 (the Nucleo's onboard
ST-Link works) is sufficient.

## Optional defmt logging

Pass `--features defmt-rtt` to enable RTT logging via `defmt`. This
streams structured logs over the SWD link as the firmware runs, at the
cost of ~6 KiB of flash:

```sh
cargo run --target thumbv7em-none-eabihf --release --features defmt-rtt
```

## Identity & key handling

The firmware bakes in a placeholder ed25519 seed (`DEV_SEED` in
`src/main.rs`). For any real deployment, replace this with one of:

* a per-device seed provisioned to the OTP region at manufacturing,
* a seed read from an external `tf-embedded-hal::SecureElement`
  (ATECC608A, SE050, OPTIGA Trust M) over I2C — the seed never leaves
  the secure chip and `sign_packet` is replaced with a `SecureElement::sign`
  call.

## Wire format

The serialised frame is the field layout that `tf-core-no-std`'s
`packet_signing_bytes` hashes, with each variable-length field prefixed
by a `u32` BE length:

```
version | packet_id | source | destination | priority | emergency
| created_at | expires_at? | signer | algorithm | payload | signature
```

Gateways that link `tf-core-no-std` can deserialise and verify these
frames directly. A reference Python decoder lives in `tools/host/lora-decode.py`.

## Status

This is a **reference firmware image**. It compiles for
`thumbv7em-none-eabihf` once `stm32wlxx-hal` is fetched. The
peripheral access pattern follows `stm32wlxx-hal` 0.6 conventions; if
you bump the HAL version the SubGhz API may shift slightly.

See [TF-0011 packet-mode spec](../../../docs/specs/TF-0011-packet-mode-and-relays.md)
for the canonical packet semantics.
