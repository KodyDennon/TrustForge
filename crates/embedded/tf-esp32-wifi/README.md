# tf-esp32-wifi — TrustForge K3

Reference firmware for the **ESP32** (Xtensa LX6) that demonstrates
the TrustForge packet-mode flow over WiFi. On boot:

1. Connects to a configured WiFi access point in STA mode.
2. Builds a TrustForge L0 packet (TF-0011) every 30 s with a mock
   sensor reading.
3. Signs it with `tf-core-no-std::packet::sign_packet` (ed25519).
4. POSTs the canonical-JSON packet to a configured TrustForge daemon
   URL (the daemon runs the HTTP-over-binary bridge introduced in
   commit `8837450`).

This example uses **std-on-ESP-IDF** (`esp-idf-sys`, `esp-idf-svc`,
`esp-idf-hal`) so we get a real OS-flavoured runtime — `Vec`, `String`,
threads, blocking sockets — backed by FreeRTOS + lwIP.

## Hardware

| Item            | Value                                      |
| --------------- | ------------------------------------------ |
| Chip            | ESP32 (Xtensa LX6, dual-core)              |
| Flash / PSRAM   | 4 MiB / 0–8 MiB depending on module        |
| Target triple   | `xtensa-esp32-espidf`                      |
| Reference board | DevKitC v4, M5Stack Core, Heltec WiFi Kit  |

## Toolchain

ESP32 (Xtensa) is **not** part of upstream rustc. You need the
Espressif fork installed via `espup`:

```sh
cargo install espup
espup install
. $HOME/export-esp.sh    # adds the +esp toolchain to PATH
cargo install ldproxy espflash
```

## Build & flash

```sh
# From this directory:
cargo +esp build --target xtensa-esp32-espidf --release
cargo +esp run   --target xtensa-esp32-espidf --release
```

The cargo runner is wired to `espflash flash --monitor` so `cargo run`
flashes the binary and opens a serial monitor.

> **Note**: this crate does not build under stock rustc. The
> Espressif toolchain (`+esp`) is required because the Xtensa target
> needs a custom LLVM backend not in the upstream Rust distribution.
> If you only have stock rustc, see K6 (`tf-esp32c3-uart`) which uses
> the RISC-V ESP32-C3 and builds with stock `rustup target add
> riscv32imc-unknown-none-elf`.

## Configuring WiFi & daemon URL

Edit the constants at the top of `src/main.rs`:

```rust
const WIFI_SSID:    &str = "TrustForge-Lab";
const WIFI_PSK:     &str = "trustforge-demo-psk";
const DAEMON_URL:   &str = "http://192.168.1.10:8080/v1/packets";
```

For production, move these into NVS and read them at boot — see
`esp-idf-svc::nvs::EspDefaultNvsPartition`.

## Wire format

This example uses the **canonical-JSON** representation (the daemon's
HTTP bridge expects JSON). Each request body is a single JSON object
with the field names and types defined in `schemas/packet.schema.json`.

The daemon re-derives the signing digest using the std-side
`tf-types::packet::packet_signing_bytes` and verifies against the
device's pinned ed25519 public key. For zero-trust deployments,
mTLS-pin the device to its instance URI.

## Status

Reference firmware. Compiles only with the Espressif toolchain
(`cargo +esp`). The cryptographic logic is target-agnostic and is
exercised by `tf-core-no-std`'s host-side tests.
