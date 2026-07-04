# ADR-0002: Minimal third-party dependency policy

- Status: Accepted
- Date: 2026-07-04
- Context: dependency audit and in-house replacement program
  (`docs/dependency-audit.md`)

## Context

TrustForge is a trust fabric: its wire formats, manifests, and envelope
handling *are* the product, and every third-party package sitting on
that surface is protocol behavior we neither authored nor gate with our
own conformance vectors. The 2026-07 audit found protocol-core behavior
delegated to ten external packages (CBOR, YAML, JWS, JSON Schema,
base64, glob matching), one of which (`serde_yaml`) was archived
upstream, plus dead dependencies and an unneeded HTTP client. Separately,
`SECURITY.md` and TF-0000 already fix the opposite rule for
cryptography: never write our own primitives.

## Decision

Dependencies are classified by where they sit:

1. **Crypto primitives — always third-party, always vetted.**
   Signature/AEAD/hash/KDF math comes from reviewed crates and packages
   (RustCrypto, dalek, noble, platform WebCrypto). Writing primitives
   in-house is prohibited. Swapping a bundled/opaque backend for a
   reviewed pure-language one (e.g. `jsonwebtoken`+`ring` →
   `rsa`/`p384`) is allowed and encouraged.

2. **Protocol codecs and envelopes — always in-house, always
   mirrored.** Anything that defines bytes-on-the-wire or
   manifest-on-disk semantics (canonical JSON, CBOR, TF-YAML, JWS
   compact form, base64, the capability glob language, JSON Schema
   validation of TrustForge schemas) is first-party code with a Rust
   implementation and a TS implementation that must not drift, gated by
   vectors under `conformance/` or fixture differentials. These modules
   implement the *subset the protocol needs* — subsetting is a feature
   (TF-YAML rejecting anchors is what makes it billion-laughs-immune).

3. **Infrastructure — third-party where owning it adds risk.**
   Async runtimes, TLS stacks, Wasm runtimes, ASN.1/X.509 parsers,
   Unicode tables, serde. These are kept, and each keep is justified in
   `docs/dependency-audit.md`.

4. **Adapters and bridges are exempt** — their entire purpose is to
   depend on the framework they adapt.

Adding a new dependency outside category 4 requires a written
justification against these categories in the PR description.

## Consequences

- The codec/envelope layer is now conformance-testable end-to-end and
  AI-implementable from our own sources — matching the
  AI-implementability requirement (a fresh implementation can be
  generated from specs + vectors without reverse-engineering a
  third-party library's quirks).
- We accept the maintenance cost of six mirrored module pairs; the
  no-drift rule (spec ↔ Rust ↔ TS ↔ vectors move together) applies to
  them as it does to specs.
- We deliberately did not chase dependency-count vanity: `thiserror`
  stays (serde-derive keeps `syn` in the graph regardless), and the
  X.509/ASN.1 parsers stay until there is a fuzzing budget.
