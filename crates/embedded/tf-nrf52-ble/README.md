# tf-nrf52-ble — TrustForge K5

Reference firmware for the **nRF52840** that exposes a BLE GATT
characteristic returning a freshly-signed TrustForge L0 packet on every
read. Useful for tap-to-sync style flows: a phone or gateway central
reads the characteristic, receives a signed packet, forwards it
upstream over its own bearer.

The pattern is the **BLE bridge profile** described in
`docs/bridges/ble-bridge.md` — the BLE central acts as a relay; it
carries a signed packet without holding the peripheral's signing key.
Forwarding authority and action authority are explicitly separate, per
TF-0011.

## Hardware

| Item            | Value                                       |
| --------------- | ------------------------------------------- |
| Chip            | nRF52840 (Cortex-M4F + 2.4 GHz radio)        |
| BLE stack       | Nordic SoftDevice S140 v7.3.0               |
| Flash / RAM     | 1 MiB / 256 KiB                             |
| Target triple   | `thumbv7em-none-eabihf`                     |
| Reference board | nRF52840-DK (PCA10056), Adafruit Feather    |

## Build

```sh
rustup target add thumbv7em-none-eabihf

# Default build — no SoftDevice required.
cargo build --target thumbv7em-none-eabihf --release

# Full BLE peripheral build:
cargo build --target thumbv7em-none-eabihf --release --features ble
```

## Flash

The `ble` feature build expects the SoftDevice S140 v7.3.0 to already
be present in flash at `0x00000000`–`0x00027000`. Flash it once with:

```sh
nrfjprog -f nrf52 --eraseall
nrfjprog -f nrf52 --program s140_nrf52_7.3.0_softdevice.hex
nrfjprog -f nrf52 --reset
```

Then flash the application:

```sh
cargo install probe-rs --features cli
cargo run --target thumbv7em-none-eabihf --release --features ble
```

The runner is `probe-rs run --chip nRF52840_xxAA`.

## GATT layout

| Item                | UUID                                          |
| ------------------- | --------------------------------------------- |
| Service             | `c0debabe-0000-1000-8000-00805f9b34fb`        |
| Signed-packet char  | `c0debabe-0001-1000-8000-00805f9b34fb`        |

The characteristic supports `READ` and `NOTIFY`. On read, the
peripheral builds a fresh packet, signs it, serialises it to the
length-prefixed binary frame format used by `tf-core-no-std`, and
returns the bytes. If the frame exceeds the negotiated MTU, the
peripheral fragments using BLE notifications.

## Identity & key handling

Same caveats as K2/K4: the baked-in seed is a placeholder. Production
deployments either use a per-device factory-provisioned seed or attach
an external secure element (the nRF52840's CryptoCell `CC310` peripheral
exposes ed25519 in HW — production firmware should drive it via the
`nrf-softdevice::raw::sd_ecb_block_encrypt` API or the open-source
`nrf-rs/nrfxlib`).

## Status

The default-feature build compiles for `thumbv7em-none-eabihf`. The
`ble` feature pulls in the `nrf-softdevice` Rust binding which, in
turn, requires the SoftDevice .hex blob to be flashed separately
(redistribution outside the scope of this repo). The TrustForge
sign/verify path is target-agnostic and exercised by `tf-core-no-std`.
