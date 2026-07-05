# Cargo Trusted Publishing

TrustForge publishes Rust crates from `.github/workflows/release.yml`.
The Cargo release job uses crates.io trusted publishing with GitHub Actions
OIDC instead of a long-lived `CARGO_REGISTRY_TOKEN` secret:

- `permissions.id-token: write`
- `rust-lang/crates-io-auth-action@v1`
- `CARGO_REGISTRY_TOKEN` populated from the action's short-lived output token
- `bash scripts/publish-crates.sh`

## Registry Setup

crates.io trusted publishing is configured per crate in crates.io registry
state. The release workflow claim configured for the TrustForge crates is:

- provider: GitHub Actions
- repository owner: `KodyDennon`
- repository name: `TrustForge`
- workflow file: `release.yml`
- environment: none

The trusted publisher entries are configured for all 31 publishable workspace
crates:

- `tf-actix-web`
- `tf-axum`
- `tf-bridge-aws`
- `tf-bridge-azure`
- `tf-bridge-doppler`
- `tf-bridge-gcp`
- `tf-bridge-vault`
- `tf-cedar`
- `tf-code-helper-example`
- `tf-core-no-std`
- `tf-core-wasm`
- `tf-decide-client`
- `tf-embedded-hal`
- `tf-hyper`
- `tf-otel`
- `tf-poem`
- `tf-prom-exporter`
- `tf-proxy`
- `tf-rego`
- `tf-revoke-redis`
- `tf-rocket`
- `tf-salvo`
- `tf-session`
- `tf-store-file`
- `tf-store-mysql`
- `tf-store-postgres`
- `tf-store-sqlite`
- `tf-tonic`
- `tf-transport`
- `tf-types`
- `tf-warp`

The standalone embedded firmware crates under `crates/embedded/` are not part
of the publishable workspace set. They target board-specific toolchains and are
intentionally excluded from the workspace and from `scripts/publish-crates.sh`.

## Release Behavior

On a tag push, the Cargo job asks crates.io for a short-lived token through the
GitHub OIDC identity of the release workflow. `scripts/publish-crates.sh` then
publishes every workspace crate that is not already present on crates.io at the
current manifest version.

The script is intentionally idempotent:

- it skips exact versions that are already published
- it treats crates.io "already exists" responses as success
- it waits through crates.io publish rate limits and retries later passes
- it excludes the bare-metal embedded crates that cannot host-verify on the CI
  runner

Do not reintroduce a long-lived `CARGO_REGISTRY_TOKEN` secret for normal
releases. If trusted publishing fails, fix the crate registry claim or the
release workflow instead of falling back to a permanent token.
