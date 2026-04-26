# tf-bootloader-example — TrustForge K9

A reference **first-stage bootloader** that demonstrates the TrustForge
verify-then-boot pattern on Cortex-M4. The bootloader pins an ed25519
boot key, verifies the application slot's signed bundle on every reset,
and only branches to the application if the signature is good.

## Bundle layout

```
Offset  Size  Field
------  ----  ---------------------------------------
0       4     magic "TFB1"  (0x54 0x46 0x42 0x31)
4       4     bundle_len (u32 LE) — total bytes incl. signature
8       4     image_len  (u32 LE) — bytes to verify (= bundle_len - 16 - 64)
12      4     reserved (zero, future flags)
16      N     image bytes (vector table + code; 16-byte aligned)
16+N    64    ed25519 signature over bytes 0..(16+N)
```

The application's reset vector lives at `app_base + 16 + 4`. SHA-256
is computed over the first `16 + image_len` bytes, then ed25519-verified
against the trailing 64-byte signature. The verifier uses the same
primitives (`ed25519-compact` + `sha2`) that
`tf-core-no-std::packet::verify_packet` uses, so the host-side signing
tool can share the implementation.

## Hardware

| Item            | Value                                       |
| --------------- | ------------------------------------------- |
| Chip (example)  | STM32F411 (any Cortex-M4 with 512 KiB flash) |
| Flash / RAM     | 128 KiB bootloader + 384 KiB app slot       |
| Target triple   | `thumbv7em-none-eabihf`                     |

## Build

```sh
rustup target add thumbv7em-none-eabihf
cargo build --target thumbv7em-none-eabihf --release
```

The bootloader binary lives at
`target/thumbv7em-none-eabihf/release/tf-bootloader-example`. Flash it
to `0x08000000` (the start of internal flash on the F411). The
application image must be flashed to `0x08020000`.

## Running the host-side tests

The verifier is exposed as both a binary and a library so it can be
unit-tested on the host:

```sh
cargo test --lib --target $(rustc -vV | sed -n 's|host: ||p')
```

The four tests in `src/lib.rs::tests` cover:

* round-trip verification of a valid bundle,
* rejection of a bad magic prefix,
* rejection of a tampered image (single-bit flip),
* rejection of a bundle signed by a different key.

## Production checklist

This is a **reference fragment**, not a hardened secure-boot stack.
Before shipping, address at least:

* **Boot key provisioning**: the placeholder `PINNED_BOOT_KEY` in
  `src/main.rs` is the all-zeros key, which guarantees every freshly
  flashed bootloader rejects every bundle (refusing-to-boot is the
  safe default before provisioning). Replace at build time via
  `option_env!("TF_BOOT_PUBKEY_HEX")` and a build-script hex-decode,
  or use the `pkc` MCU option-byte mechanism (STM32H7 PKA cluster) to
  pin the key in OTP.
* **Anti-rollback**: store a monotonic counter in the last flash page
  and refuse bundles with a header version below it.
* **A/B failsafe**: provision two slots and a "boot status" word so a
  bad upgrade can fall back to the previously-known-good image.
* **RDP / PCROP**: enable read-out protection on the bootloader
  region so an attacker with debug access can't extract the boot key
  or replace the verifier with a no-op.
* **MPU lockdown**: the bootloader should configure the MPU to make
  its own region read-only before jumping to the application.

## systemd-style alternative

For non-MCU targets (TrustForge daemon updates on a Linux SBC), the
same pattern is implemented as a systemd `ExecStartPre=` step that
runs `tf bundle verify --pin-key /etc/trustforge/boot.pub
/var/lib/trustforge/next.tfbundle` before unlocking the next stage.
The bundle layout is identical; only the verification host changes.

## Status

Compiles cleanly for `thumbv7em-none-eabihf`. Library tests pass on
host. The verifier logic is the production path; the binary entry
point and the linker-script glue are illustrative for a single-slot
F411-class layout — production multi-slot bootloaders extend this
with a slot-selector and the production-checklist items above.
