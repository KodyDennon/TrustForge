# tf-core-wasm

TrustForge core surface compiled to `wasm32-unknown-unknown` for in-process
use from TS / JS adapters. Re-exports the security-critical functions from
[`tf-types`](../tf-types/) — canonical-JSON, packet verify, policy
evaluation, ed25519 verify, session-migration verify — so JS callers do not
need an HTTP round-trip to a daemon to get a TrustForge decision.

## Status

Phase-0 draft, like the rest of the repo. Not production-ready.

## Prerequisites

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## Build

```sh
./build.sh
```

This produces three bundles under `dist/`:

- `dist/web/`     — for direct browser `<script type="module">` use
- `dist/node/`    — for Node.js / Bun (`require` or ESM)
- `dist/bundler/` — for Webpack / Rollup / Vite consumers

Or build the raw `wasm32` artifact directly:

```sh
cargo build -p tf-core-wasm --target wasm32-unknown-unknown --release
```

## Use from TypeScript

```ts
import init, { canonicalize, verify_packet } from "@trustforge/core-wasm";

await init();

const c = canonicalize({ z: 1, a: 2 }); // '{"a":2,"z":1}'

const result = verify_packet(packet, publicKeyBase64, "2026-04-25T00:00:00Z");
if (!result.ok) {
  throw new Error(`packet rejected: ${result.reason}`);
}
```

## Exports

| Function                  | Returns                              |
|---------------------------|--------------------------------------|
| `canonicalize(value)`     | canonical-JSON string                |
| `verify_packet(p, pk, now)` | `{ok: bool, reason: string \| null}` |
| `evaluate_policy(manifest_json, query)` | `PolicyDecision`         |
| `ed25519_verify(pk, msg, sig)` | `bool`                          |
| `verify_session_migration(m_json, pk, last_gen)` | `{ok, reason}` |

All return values are plain JS values via `serde-wasm-bindgen`; binary
inputs (public keys, signatures) are base64-encoded strings; payloads are
`Uint8Array`.

## Tests

Rust-side smoke tests live under `tests/`. The cross-language byte-for-byte
parity test (TS canonicalize vs. wasm canonicalize) lives in
`tools/tf-types-ts/tests/wasm-core.test.ts` and is skipped when the wasm
bundle has not been built.
