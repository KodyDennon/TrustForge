# tf-cedar

TrustForge policy engine adapter for AWS Cedar. Evaluate complex authorization policies locally against TrustForge capabilities.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-cedar
```

## Overview

TrustForge Cedar policy engine adapter.

Wraps the upstream `cedar-policy` crate and exposes a thin façade that
produces TrustForge `PolicyDecision` records from Cedar `Authorizer`
responses. This crate is opt-in: `tf-types` only depends on it when the
`cedar` feature is enabled, so lightweight deployments never pull Cedar
in transitively.

Translation rules:

* `PolicyQuery.subject`  -> Cedar `principal` UID. The translator parses
  the subject as a Cedar entity reference; if it isn't already a valid
  `Type::"id"` form (the common case for `tf:actor:…`) the engine wraps
  it as `Subject::"<escaped>"`.
* `PolicyQuery.action`   -> `Action::"<action>"`.
* `PolicyQuery.target`   -> `Resource::"<target>"` when present, else
  `Resource::"unknown"` (Cedar requires a resource UID; the policies
  are responsible for handling that placeholder).
* `PolicyQuery.context`  -> Cedar context built via JSON.

Cedar's `Authorizer::is_authorized` returns Allow/Deny + a list of
contributing policy IDs. We map them to the `PolicyDecision` shape:
`decision` is `"allow"` or `"deny"`; `rule_id` is the first
contributing policy id; `reason` summarises diagnostics. Errors during
evaluation (e.g. malformed entities) are surfaced via the explicit
`CedarError` returned from `new`; runtime evaluation errors degrade to
a safe `deny` decision with a descriptive reason.

## Links

- API docs: [docs.rs/tf-cedar](https://docs.rs/tf-cedar)
- Source: [crates/tf-cedar](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-cedar)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
