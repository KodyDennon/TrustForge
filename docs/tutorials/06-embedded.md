# 06 — Embedded

Goal: flash one of the embedded examples under
`crates/embedded/`, mint an actor identity onto the device, and
verify a packet it produces from your laptop. About 60 minutes,
plus toolchain installation if you have not done embedded Rust
before.

By the end you will have:

- A working firmware on a real (or simulated) MCU.
- A signed `.tfpkt` produced by the device.
- A proof event verifying the device's signature on your laptop.

This tutorial assumes you have completed
[01 Getting started](01-getting-started.md).

## Pick an example

| Crate | MCU | Carrier | Difficulty |
|---|---|---|---|
| `tf-stm32wl-lora` | STM32WLE5JC | LoRa (sub-GHz) | Medium |
| `tf-rp2040-picow` | Pi Pico W | WiFi | Easy |
| `tf-esp32-wifi` | ESP32 | WiFi | Easy |
| `tf-esp32c3-uart` | ESP32-C3 | UART | Easy |
| `tf-nrf52-ble` | nRF52840 | BLE | Medium |
| `tf-avr-atmega328` | ATmega328 | none — sign-only | Hard |
| `tf-bootloader-example` | Cortex-M | n/a — signed boot | Hard |

This walkthrough uses **`tf-rp2040-picow`** (Pi Pico W) because
the toolchain is widely available and a working device is
inexpensive. The flow is the same on the other targets; consult
each crate's README for board-specific notes.

If you do not have hardware, the LoRa example ships with a
deterministic xorshift64* simulator under
`tools/tf-packet/src/simulate-lora.ts` that you can use to
exercise the protocol entirely on your laptop.

## Step 1 — Install the embedded toolchain

```bash
rustup target add thumbv6m-none-eabi
cargo install probe-rs --features cli
```

(For a different chip, install the matching target — see the
crate README.)

Plug your Pi Pico W into USB. Hold the BOOTSEL button while
plugging in to put it into mass-storage bootloader mode (or use
`probe-rs` directly via SWD if you have a debug probe).

## Step 2 — Mint a device identity placeholder

The device generates its own keypair on first boot, but you can
pre-mint a placeholder so the daemon already knows the actor
URI you will see:

```bash
TF_VAULT_PASS=dev-pw \
    bun run tools/tf-cli/src/cli.ts actor create \
    --type device --name pico-01 --domain example.com
```

Result: `tf:actor:device:example.com/pico-01`. The actual key
material on the device will be different; you will reconcile
them in step 5.

## Step 3 — Build and flash

```bash
cd crates/embedded/tf-rp2040-picow
cargo build --release --target thumbv6m-none-eabi
```

If you used the BOOTSEL bootloader, copy the resulting `.uf2`
onto the device's USB mass-storage drive. If you have a probe,
run:

```bash
cargo flash --chip RP2040 --release
```

The device boots and prints to its USB serial:

```
[tf-pico] boot
[tf-pico] flash region 0x10100000 holds key bytes? no
[tf-pico] minting first-boot ed25519 keypair
[tf-pico] writing key to flash...
[tf-pico] actor URI: tf:actor:device:example.com/pico-01-<hex>
```

The `<hex>` suffix is derived from the chip's unique id so each
device gets a distinct URI even if the firmware is identical.

## Step 4 — Connect to the device's USB serial

```bash
# Linux/macOS
screen /dev/ttyACM0 115200
# or:
minicom -D /dev/ttyACM0
```

You should see a prompt:

```
tf-pico> 
```

Commands available on the device:

- `pubkey` — print the device's ed25519 public key (base64).
- `sign <hex>` — sign the given hex bytes, print the signature.
- `verify <hex> <sig>` — verify a signature.
- `mkpkt <recipient> <payload-hex>` — build and sign a `.tfpkt`,
  print it as base64.

## Step 5 — Reconcile the actor URI

The daemon expects to verify packets from
`tf:actor:device:example.com/pico-01-<hex>`. Tell the daemon
about the device's actual key:

```bash
# Capture the device's pubkey from `pubkey` over serial.
DEV_PUBKEY=…  # base64

bun run tools/tf-cli/src/cli.ts actor import \
    --uri tf:actor:device:example.com/pico-01-${HEX} \
    --pubkey $DEV_PUBKEY \
    --type device
```

Now the daemon trusts that pubkey for that URI.

## Step 6 — Make the device sign a packet

On the serial console:

```
tf-pico> mkpkt tf:actor:service:example.com/intake hello
[tf-pico] packet (base64):
TFPK...AA== [...]
```

Copy the base64 payload to your laptop:

```bash
echo "TFPK..." | base64 -d > /tmp/from-pico.tfpkt
```

## Step 7 — Verify the packet

```bash
bun run tools/tf-cli/src/cli.ts packet verify --in /tmp/from-pico.tfpkt
# packet valid:
#   from:    tf:actor:device:example.com/pico-01-<hex>
#   to:      tf:actor:service:example.com/intake
#   ts:      …
#   payload: 5 bytes
#   signature: ok (ed25519)
#   nonce:     fresh
```

## Step 8 — Send a sealed packet to the device (optional)

If your device example supports recipient sealing (the LoRa,
ESP32, and nRF examples do; the AVR example is sign-only), you
can encrypt a payload to the device's recipient X25519 key:

```bash
DEV_X25519_PK=…  # printed at boot or via `xpubkey` command

bun run tools/tf-cli/src/cli.ts packet sign \
    --from tf:actor:service:example.com/intake \
    --to   tf:actor:device:example.com/pico-01-${HEX} \
    --payload /tmp/cmd.json \
    --seal-to $DEV_X25519_PK \
    --out /tmp/cmd.tfpkt

# Send the file over WiFi/BLE/serial; on the device:
tf-pico> ingest <base64-of-cmd.tfpkt>
[tf-pico] packet from tf:actor:service:example.com/intake
[tf-pico] decoded payload: { "led": "on" }
```

The device only accepts packets where the signature is valid and
the recipient X25519 key matches its own — exactly the same
checks the desktop daemon performs.

## Step 9 — Constrained-mode considerations

Embedded deployments typically run under
`tf-constrained-compatible`:

- LoRa duty-cycle limits force packet-mode delivery.
- The offline revocation list mechanism (sealed, signed list with
  a freshness window) is how the device learns about revoked
  upstream actors.
- The device's own key is bound to flash or a secure element; do
  not move it to a different device.

See [`../profiles/constrained-profile.md`](../profiles/constrained-profile.md)
and [`../topologies/mesh-and-relay.md`](../topologies/mesh-and-relay.md).

## Step 10 — Bootloader binding (advanced)

The `tf-bootloader-example` crate demonstrates signed boot:
the bootloader verifies the firmware's signature against a
TrustForge-issued certificate before jumping into it. This binds
firmware deployment to the same proof events that gate any other
action. Use it when:

- Field-deployed devices must reject unsigned firmware.
- Firmware updates must be auditable in the same ledger as
  runtime actions.
- The device boundary should be enforced cryptographically, not
  just by physical access controls.

The bootloader README walks through the partition layout and
the per-target signing recipe.

## What you have learned

- Embedded TrustForge uses the same packet format as desktop;
  the wire bytes are identical.
- Device identities are minted on the device, not assigned from
  the daemon. The daemon imports the public key after first
  boot.
- Sealed packets work across the boundary in both directions.
- Constrained mode trades live sessions for offline-first
  primitives (revocation lists, delivery receipts,
  proof-of-forwarding).

## What to read next

- [07 Bridges](07-bridges.md) — accept SPIFFE / OAuth / WebAuthn
  on the desktop side.
- [`../profiles/constrained-profile.md`](../profiles/constrained-profile.md)
  — every MUST and SHOULD for the constrained profile.
- [`../topologies/mesh-and-relay.md`](../topologies/mesh-and-relay.md)
  — relay multiple devices through a single gateway.
- The per-crate READMEs under
  [`../../crates/embedded/`](../../crates/embedded/).
