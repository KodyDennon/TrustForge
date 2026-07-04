# tf-bridge-gcp

TrustForge identity bridge for GCP. Translate GCP credentials, roles, and policies into cryptographic TrustForge actors and capabilities.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-bridge-gcp
```

## Overview

TrustForge bridge for GCP IAM.

Three primary entry points:

1. [`verify_gcp_id_token`] — verify a Google-issued OIDC ID token by
   fetching the JWKS at
   `https://www.googleapis.com/oauth2/v3/certs` (override for tests)
   and checking the RS256 signature, issuer, and audience.

2. [`service_account_to_actor`] — translate a verified GCP service
   account principal into a TrustForge `ActorIdentity`.

3. [`gcp_iam_role_to_capabilities`] — map common predefined GCP roles
   (`roles/storage.objectViewer`, `roles/iam.serviceAccountUser`,
   etc.) into TrustForge capabilities.

## Links

- API docs: [docs.rs/tf-bridge-gcp](https://docs.rs/tf-bridge-gcp)
- Source: [crates/bridges/tf-bridge-gcp](https://github.com/KodyDennon/TrustForge/tree/main/crates/bridges/tf-bridge-gcp)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
