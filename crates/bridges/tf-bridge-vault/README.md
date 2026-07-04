# tf-bridge-vault

TrustForge identity bridge for VAULT. Translate VAULT credentials, roles, and policies into cryptographic TrustForge actors and capabilities.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-bridge-vault
```

## Overview

TrustForge bridge for HashiCorp Vault.

Two primary entry points:

1. [`vault_token_to_actor`] — given a `vaultrs::client::VaultClient`
   (or any client that exposes `auth/token/lookup-self`), translate
   the live token into a TrustForge `ActorIdentity`.

2. [`vault_secret_path_to_capability`] — translate a secret-mount +
   path into a TrustForge `Capability` that grants
   `vault.kv.read` against the path as a target glob.

The bridge intentionally does not embed the secret itself — only the
authority to retrieve it. The daemon is responsible for actually
reading the secret when the policy engine grants the capability.

## Links

- API docs: [docs.rs/tf-bridge-vault](https://docs.rs/tf-bridge-vault)
- Source: [crates/bridges/tf-bridge-vault](https://github.com/KodyDennon/TrustForge/tree/main/crates/bridges/tf-bridge-vault)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
