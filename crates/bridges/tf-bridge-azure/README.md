# tf-bridge-azure

TrustForge identity bridge for AZURE. Translate AZURE credentials, roles, and policies into cryptographic TrustForge actors and capabilities.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-bridge-azure
```

## Overview

TrustForge bridge for Azure AD / Entra ID.

Three primary entry points:

1. [`verify_azure_jwt`] — verify an Azure-issued JWT (managed
   identity, app registration, user) against the tenant's discovery
   JWKS at
   `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`.

2. [`managed_identity_to_actor`] — translate verified Azure claims
   into a TrustForge `ActorIdentity`, using the `oid` (object id) as
   the stable principal identifier.

3. [`azure_role_assignment_to_capabilities`] — map common Azure RBAC
   role names (built-in roles such as "Storage Blob Data Reader") to
   TrustForge capabilities.

Note on dependencies: Azure JWT *verification* only requires
`jsonwebtoken` + `reqwest`. The `azure_identity` crate is for
*acquiring* outbound tokens (DefaultAzureCredential, federated
workload identity) — not what this bridge does. Adding it would pull
in the entire azure_core stack with no functional benefit, so we
omit it. Future revisions that need outbound token issuance (so the
daemon can call back to Azure on the user's behalf) should add it
behind a feature flag.

## Links

- API docs: [docs.rs/tf-bridge-azure](https://docs.rs/tf-bridge-azure)
- Source: [crates/bridges/tf-bridge-azure](https://github.com/KodyDennon/TrustForge/tree/main/crates/bridges/tf-bridge-azure)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
