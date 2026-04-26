# tf-esp32c3-uart — TrustForge K6

Reference firmware for the **ESP32-C3** (RISC-V RV32IMC) that signs
TrustForge L0 packets and prints them over UART0 at 115_200 baud. The
host attached to the UART acts as a relay — it receives the framed
bytes and forwards them to a TrustForge daemon over its own bearer.

This is the simplest constrained-mode demonstrator: no radio, no IP
stack, just sign-and-print. The signature binds the payload, so the
relay can carry the packet without being trusted to read or modify it
(per TF-0011 the relay is a first-class actor with separate forwarding
authority and action authority).

## Hardware

| Item            | Value                                       |
| --------------- | ------------------------------------------- |
| Chip            | ESP32-C3 (single-core RV32IMC @ 160 MHz)    |
| Flash / RAM     | 4 MiB / 400 KiB                             |
| Target triple   | `riscv32imc-unknown-none-elf`               |
| Reference board | ESP32-C3-DevKitM-1, Seeed XIAO C3           |

## Build

The C3 is the easiest Espressif chip to target from stock Rust — it's
RISC-V with no Xtensa custom-LLVM dance:

```sh
rustup target add riscv32imc-unknown-none-elf

# Default-feature build — exercises sign+serialise, links cleanly.
cargo build --target riscv32imc-unknown-none-elf --release

# Full UART-print build with esp-hal.
cargo build --target riscv32imc-unknown-none-elf --release --features hal
```

## Flash & monitor

```sh
cargo install espflash
cargo run --target riscv32imc-unknown-none-elf --release --features hal
```

The runner is `espflash flash --monitor`, which flashes the ELF and
opens a serial monitor on `/dev/cu.usbserial-*`.

## Note on `tf-embedded-hal`

This crate **does not** depend on `tf-embedded-hal`. The HAL crate
re-exports `heapless::spsc::Queue`, which requires atomic load/store —
something `riscv32imc` (no `A` extension) lacks. C-class chips with
the `A` extension (ESP32-C6 / -H2 / -P4, RV32IMAC) can pull in the HAL
without changes; for the C3, hide the spsc adapter behind
`cfg(target_has_atomic = "8")` or use a portable-atomic shim if you
need the HAL surface here.

The TrustForge sign/verify path itself has zero atomic dependencies and
links cleanly on RV32IMC.

## Wire format

Each line emitted on UART0 looks like:

```
TF-FRAME 00000001310000003c706b742d63332d3030303030303031...0102...
```

The hex dump after `TF-FRAME ` is the same length-prefixed binary
frame K2 / K4 / K5 emit (see `serialise_packet` in `src/main.rs`). A
host-side relay (e.g. `tools/host/uart-relay.py`) reads the line and
POSTs the bytes to the daemon.

## Status

Compiles for `riscv32imc-unknown-none-elf` out of the box. Default
build links cleanly; `--features hal` pulls in `esp-hal` 0.21 for the
real UART path and the boot-up routine.
