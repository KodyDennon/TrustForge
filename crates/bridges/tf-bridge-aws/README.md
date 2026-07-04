# tf-bridge-aws

TrustForge identity bridge for AWS. Translate AWS credentials, roles, and policies into cryptographic TrustForge actors and capabilities.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-bridge-aws
```

## Overview

TrustForge bridge for AWS IAM.

Three primary entry points:

1. [`verify_aws_sigv4_request`] — verify a SigV4-signed inbound HTTP
   request by replaying it (or its signed headers) against AWS STS
   `GetCallerIdentity`. STS is the canonical SigV4 verifier — only AWS
   knows the secret access key, so the only way for a third party to
   confirm a SigV4 signature is to ask STS who signed it.

2. [`assume_role_token_to_actor`] — translate a STS `AssumeRole`
   response (or any `AssumedRoleUser` block we have in hand) into a
   TrustForge `ActorIdentity`.

3. [`iam_policy_to_capabilities`] — translate an IAM policy JSON
   document (the JSON shape returned by `aws iam get-policy-version`)
   into TrustForge `Capability` values, with `NegativeCapability`
   entries for explicit `Deny` statements.

Trust-domain note: AWS principals project into the
`aws.amazon.com/<account-id>` trust domain so they sit alongside other
cloud providers (`gcp.googleapis.com/<project>`,
`login.microsoftonline.com/<tenant>`).

## Links

- API docs: [docs.rs/tf-bridge-aws](https://docs.rs/tf-bridge-aws)
- Source: [crates/bridges/tf-bridge-aws](https://github.com/KodyDennon/TrustForge/tree/main/crates/bridges/tf-bridge-aws)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
