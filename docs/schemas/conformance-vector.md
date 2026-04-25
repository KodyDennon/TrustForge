# TrustForge Conformance Vector

> `$id`: `https://trustforge.io/schemas/v0/conformance-vector.schema.json`

A single conformance vector consumed by tf-conformance runners. Vectors describe a category, the inputs the runner needs, and the canonical output (or expected error) every conformant implementation must produce. The format is the wire-level record that backs every category file under conformance/ — schema, signature, chain, framing, session, bridge, relay, trust-overlay, guard, packet, evidence, federation.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `vector_version` | `"1"` | ✓ | Version of the conformance-vector schema itself. |
| `category` | `"schema"` \| `"signature"` \| `"chain"` \| `"framing"` \| `"session"` \| `"bridge"` \| `"relay"` \| `"trust-overlay"` \| `"guard"` \| `"packet"` \| `"evidence"` \| `"federation"` \| `"profile"` \| `"negative-capability"` \| `"ai-implementation"` \| `"security-regression"` | ✓ | Vector category. The runner this vector is dispatched to. |
| `id` | string (minLength: 1) | ✓ | Stable, human-readable identifier for this vector. Implementations cite this id in their conformance reports. |
| `spec_ref` | string | · | TF-XXXX or DECISIONS.md reference establishing the normative behavior under test. |
| `description` | string | · | Human-readable summary of what this vector exercises. |
| `tags` | array of string (minLength: 1) | · | Free-form tags. Common: 'must', 'should', 'security', 'ai-safety', 'pq', 'offline'. |
| `input` | object | · | Inputs supplied to the runner. Shape varies per category; runners validate the shape they receive. |
| `expected` | _unknown_ | · | Canonical expected output. Implementations are conformant when their output matches under the canonicalization rule for the category. Implementations may emit any JSON value here. |
| `expect` | `"valid"` \| `"invalid"` \| `"allow"` \| `"deny"` \| `"log-only"` \| `"approval-required"` \| `"escalate"` | · | Outcome label when the runner produces a single boolean. Use `expected` for full output equality. |
| `expected_error` | object | · | Expected validation/runtime error when `expect` is `invalid`. Empty object means 'any error'. |
| `fixture` | string | · | Path (relative to repo root) of a YAML/JSON fixture supplying the input. |
| `applies_to_profiles` | array of string (pattern: `^tf-[a-z0-9-]+-compatible$`) | · | Profile labels this vector belongs to. Empty / omitted means 'every profile'. |
