# Adding a new TrustForge schema

Checklist for every new `<name>.schema.json` landing in `schemas/`:

1. **File placement** — new schema goes in `schemas/<name>.schema.json`.
2. **`$id`** — must be `https://trustforge.io/schemas/v0/<name>.schema.json` until we cut v1.
3. **`$schema`** — `https://json-schema.org/draft/2020-12/schema`.
4. **Lint rules** — every object sets `additionalProperties: false` (or `additionalProperties: true` for deliberately-open sub-objects, or `propertyNames` for pattern-keyed maps). Every property has a `description`.
5. **Cross-schema references** — use `$ref: "_common.schema.json#/$defs/<Name>"` for shared primitives; don't redefine `RiskClass`, `ActorId`, etc.
6. **Fixtures** — at minimum one `schemas/fixtures/<name>/valid/*.yaml` plus three `schemas/fixtures/<name>/invalid/*.yaml` each paired with a `.expected-error.yaml` manifest.
7. **Run `bun run tools/tf-schema/src/cli.ts validate-all`** — must report zero mismatches.
8. **Run `bun run tools/tf-schema/src/cli.ts lint`** — must report zero issues.
9. **Regenerate codegen + docs + parity** — all four of:
   ```bash
   bun run tools/tf-schema/src/cli.ts codegen --target ts
   bun run tools/tf-schema/src/cli.ts codegen --target rust
   bun run tools/tf-schema/src/cli.ts codegen --target docs
   bun run tools/tf-schema/src/cli.ts parity
   ```
   CI fails if any of these produce a diff that wasn't committed.
10. **Run `cargo test --workspace`** — verifies the new Rust types deserialize every valid fixture and that `tests/parity.rs` accepts every entry in `conformance/parity.yaml`.

See `docs/superpowers/specs/2026-04-24-trustforge-foundation-design.md` for the overall design.
