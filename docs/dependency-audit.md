# Dependency Audit & In-House Replacement Program

Status: executed July 2026 (waves 1–2 complete). This document is the
inventory, the verdict per dependency, and the record of what was
replaced with in-house code. The policy criteria live in
[ADR-0002](adr/0002-minimal-third-party-dependency-policy.md).
The active execution roadmap for the broader replacement program lives
in [Dependency Replacement Roadmap](dependency-replacement-roadmap.md).

## Principles

1. **No custom cryptography** (per `SECURITY.md` and TF-0000). Crypto
   *primitives* are always vetted third-party crates/packages. Crypto
   *envelopes and codecs* (JWS compact form, CBOR framing, canonical
   JSON, base64) are protocol surface and are owned in-house, built on
   those primitives.
2. **Protocol-core codecs are in-house, mirrored, and
   conformance-gated.** Every codec exists as a Rust/TS pair with
   byte-level or tree-level parity vectors under `conformance/` or
   fixture differentials. This follows the pattern set by canonical
   JSON (`canonical.rs` / `canonical.ts`).
3. **Runtimes, TLS, ASN.1/X.509 parsing, Unicode tables, and
   framework adapters stay third-party.** Owning them adds risk, not
   sovereignty.

## In-house modules created (waves 1–2)

| Module (Rust / TS) | Replaces | Parity gate |
|---|---|---|
| `tf-types/src/encoding.rs` | `base64` crate | RFC 4648 vectors + exhaustive round-trip |
| `tf-types/src/glob.rs` | `regex` (glob-conversion sites) | unit suite; linear-time DP, no backtracking blowup |
| `tf-types/src/cbor.rs` / `core/cbor.ts` | `ciborium`, `ciborium-ll`, `cbor-x` | `conformance/binary-format-vectors.yaml` byte parity (Rust+TS); RFC 8949 appendix-A vectors; hardened-decoder tests |
| `tf-types/src/yaml.rs` / `core/yaml.ts` | `serde_yaml` (deprecated upstream), `yaml` (npm) | every repo `.yaml` parsed identically to the reference parser (238 files byte-for-byte tree-equal), plus Rust↔TS cross-language dump comparison |
| `tf-types/src/jws.rs` / `core/jws.ts` | `jsonwebtoken` (and its bundled `ring`), `jose` | negative suites in both languages: tampered sig, `alg:none`, key-type/alg confusion, expiry+leeway, iss/aud; bridge test suites end-to-end |
| `tf-schema/src/validator.ts` | `ajv`, `ajv-formats` | all 122 schema fixtures (48 valid / 74 invalid with pinned keyword+path expectations) — identical to the ajv baseline |

Also removed without replacement (dead weight):

- `hash-wasm` (tf-types-ts) — zero imports.
- `@peculiar/webcrypto` (dev) — Bun ships native WebCrypto.
- `ciborium`/`ciborium-ll` in `tf-core-no-std` — declared, never used.
- `base64` in `tf-bridge-doppler` — declared, never used.
- `reqwest` in `tf-proxy` — replaced by the already-present
  `hyper`/`hyper-util` client (upstream is documented plain-HTTP; TLS
  terminates at the listener).
- `reqwest` in `tf-decide-client` — replaced by an in-house HTTP/1.1
  client from `tf-transport`, scoped to local `tf-daemon` decide calls.
  The public `reqwest::Client` customization API was removed; use
  `TfDecideClient::new(...).with_timeout(...)`.
- `reqwest` in `tf-prom-exporter` — replaced by an in-house HTTP/1.1
  GET helper from `tf-transport`, scoped to local daemon admin scraping
  and `/metrics` integration tests.
- SQLite as the only local embedded store — `tf-store-file` now provides
  a first-party file-backed store with no database dependency, proof-log
  checksums, evidence checksum sidecars, and compaction. It still uses
  the current `serde_json::Value` trait boundary until the planned
  first-party JSON migration lands.

Release and generated-surface fixes shipped with this slice:

- `scripts/publish-crates.sh` now publishes regular native Rust
  workspace crates outside `crates/`, starting with
  `tf-prom-exporter`.
- TS RPC and agent-contract generators now emit imports from
  `@trustforge-protocol/types`, so generated files typecheck in the
  monorepo and in downstream workspaces.

## Deliberate keeps

| Dependency | Why it stays |
|---|---|
| `ed25519-dalek`, `x25519-dalek`, `p256`, `p384`, `rsa`, `fips204`, `chacha20poly1305`, `sha2`, `sha1`, `blake3`, `hkdf`, `hmac`, `argon2`, `rand`, `ed25519-compact`, `@noble/*` | Crypto primitives — hard rule, never in-house. (`p384`, `rsa` were *added* by wave 2c to replace `jsonwebtoken`+`ring` with pure-Rust RustCrypto equivalents.) |
| `serde`, `serde_json` | Foundational; canonical JSON form is already in-house on top. |
| `tokio`, `bytes`, `futures`, `tokio-util` | Async runtime. |
| `wasmtime` | Plugin sandbox. Reimplementing a Wasm runtime is out of the question. |
| `unicode-normalization` | Unicode data tables (NFC for `canonical.rs`). |
| `x509-parser`, `@peculiar/asn1-*`, `@peculiar/x509` (dev) | ASN.1/DER parsing is where parser vulns live; revisit only with a fuzzing budget. |
| `rustls` / `tokio-rustls` / `rustls-pemfile` | TLS. |
| `flate2` | DEFLATE (pure-Rust `miniz_oxide` backend). Not worth owning. |
| `regex` | **Shrunk, not removed**: now used only where `schemas/policy.schema.json` promises "Regex (ECMAScript)" for `action_pattern`/`subject_pattern`, and `evidence` event-type filters. All internal glob matching moved to `glob.rs`. See "known drift" below. |
| `heapless`, `serde-json-core` | no-std kernels. |
| OpenTelemetry (Rust + TS) | Already optional deps; observability plumbing. |
| `ureq` | Optional `http-anchors` feature only. |
| `thiserror` | Evaluated for removal (stretch): rejected — `serde`'s derive feature keeps `syn`/`quote` in the build graph regardless, so dropping thiserror churns 15 crates' error types for no measurable build or supply-chain win. |
| `clap`, `tracing` | Binary-only (tf-proxy) CLI/logging. |
| Next.js / React (site), framework adapters (`crates/adapters/*`, `crates/bridges/*`, `tools/adapters/*`) | Adapters exist to wrap third-party frameworks; the site is not protocol surface. Optional follow-up: drop `framer-motion`/`lucide-react` from the site. |

## Scorecard

- npm packages (workspace lockfile): **501 → 488**.
- Rust unique crate versions (workspace graph): **770 → 761** (the
  bulk of the remaining graph is framework adapters and `wasmtime`).
- `tf-types` direct dependencies: 27 → 25, and the removed set
  included `ring` (C/asm) and the archived `serde_yaml`; the additions
  are pure-Rust RustCrypto primitives.
- **The entire codec/envelope layer of the protocol — base64, glob,
  canonical JSON, CBOR, YAML, JWS, JSON Schema validation — is now
  first-party in both reference languages.**

## Known drift & follow-ups

- `schemas/policy.schema.json` documents `action_pattern` /
  `subject_pattern` as "Regex (ECMAScript)", but the Rust engine uses
  the `regex` crate (no backreferences/lookahead, different escapes).
  This drift **predates this audit**. Options: narrow the spec promise
  to the common subset, or define the pattern language as TF glob in a
  spec revision. Tracked for a spec decision.
- `conformance/negative-capability-vectors.yaml` used YAML anchors —
  the one construct outside the TF-YAML subset — and was normalized by
  expanding the alias (semantics unchanged; loaders untouched).
- Static cross-language JWS vectors (signed-token fixtures checked into
  `conformance/`) would strengthen 2c beyond the current per-language
  negative suites. Follow-up.
- TF-YAML intentionally rejects: anchors/aliases, tags, multi-document
  streams, complex keys, non-finite floats (Rust). Infra fixtures that
  need k8s-style multi-doc YAML (`tools/native/*/manifests`) are not
  parsed by TrustForge code.
- JS-number semantics: TF-YAML/TS cannot distinguish `1.0` from `1`;
  Rust preserves the float. Both canonicalize to `"1"` (that behavior
  is itself covered by `canonical-vectors.yaml`).

## Maintenance rules

- A new third-party dependency in `crates/` or `tools/` (outside
  adapters/bridges) needs a justification against ADR-0002 in the PR.
- The in-house codecs are spec surface: changing `cbor`, `yaml`, `jws`,
  `encoding`, `glob`, or `validator` requires updating the matching
  mirror implementation and conformance vectors in the same change.
