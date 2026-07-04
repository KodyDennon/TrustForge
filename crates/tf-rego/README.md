# tf-rego

TrustForge policy engine adapter for OPA Rego. Evaluate dynamic, fine-grained policies using Open Policy Agent semantics.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-rego
```

## Overview

TrustForge Rego policy engine adapter.

Wraps the upstream `regorus` Rego interpreter (a pure-Rust port of OPA's
evaluation core) and exposes a thin façade that produces TrustForge
`PolicyDecision` records from the raw Rego output. This crate is opt-in:
`tf-types` only depends on it when the `rego` feature is enabled.

Translation rules:

* `PolicyQuery` is rendered as a JSON object with the same keys
  (`subject`, `instance`, `action`, `target`, `context`,
  `negative_capabilities`, `enforcement_level`, `now`) and supplied as
  the engine's `input`.
* The engine evaluates `data.trustforge.allow`. The result MAY be a
  plain boolean (allow/deny) or a richer object of the form
  `{decision, reason, rule_id}`. Both shapes are accepted.
* Rego compilation errors become `RegoError::Policy`. Runtime evaluation
  errors collapse into a safe `deny` decision so a single bad request
  cannot crash the daemon.

## Links

- API docs: [docs.rs/tf-rego](https://docs.rs/tf-rego)
- Source: [crates/tf-rego](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-rego)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
