# npm Trusted Publishing

TrustForge publishes npm packages from `.github/workflows/release.yml`.
The workflow is configured for npm trusted publishing with GitHub Actions OIDC:

- `permissions.id-token: write`
- Node `24.x`
- latest npm CLI before publish
- `npm publish --workspaces --access public --provenance`
- root package publish with `npm publish --access public --provenance`

## Registry Setup

npm trusted publishing is configured per package in npm registry state, not in
`package.json`. The npm registry exposes this through the trust API, so the repo
includes a helper:

```bash
node scripts/configure-npm-trusted-publishing.mjs
```

The script:

- infers the GitHub repository from `gh repo view`
- validates `.github/workflows/release.yml` exists and has OIDC-ready npm publish settings
- refuses to run unless the discovered npm package set exactly matches the 36-package TrustForge inventory
- validates every npm package's `repository.url` matches the GitHub repository
- verifies every package exists on the npm registry before mutating trust settings
- discovers the root package plus all npm workspaces
- configures npm trusted publishing for each package
- re-reads npm trust settings for every package after setup and fails if any package is missing the expected config

- provider: GitHub Actions
- repository: `KodyDennon/TrustForge`
- workflow file: `release.yml`
- permission: `createPackage` (`npm publish`)

Use `--dry-run` to inspect the package list without changing npm:

```bash
node scripts/configure-npm-trusted-publishing.mjs --dry-run
```

If a package already has a different trusted publisher configuration, the script
stops instead of overwriting it. Use `--replace` only after confirming the old
configuration is obsolete:

```bash
NPM_TOKEN=... NPM_OTP=123456 \
  node scripts/configure-npm-trusted-publishing.mjs --replace
```

For one package:

```bash
node scripts/configure-npm-trusted-publishing.mjs \
  --package @trustforge-protocol/core
```

## Auth Requirements

The npm trust API requires:

- an npm token with write access to each package
- npm 2FA enabled on the account

The script reads `NPM_TOKEN` from the environment first. If omitted, it can use
a token already present in `.npmrc` or `~/.npmrc`. It never prints the token or
OTP.

For TOTP accounts, provide a current one-time password:

```bash
NPM_OTP=123456 node scripts/configure-npm-trusted-publishing.mjs
```

For passkey/WebAuthn accounts, omit `NPM_OTP`. If npm returns a web auth
challenge, the script opens npm's `authUrl`, waits for passkey confirmation, and
polls npm's `doneUrl` for the short-lived OTP needed by the trust API.

If the registry returns a plain `403` without a web challenge, the token does
not have enough package-write/trust permission for this operation or npm did not
offer passkey auth for that endpoint/token combination. In that case, log in
again with npm web auth or provide a token that can manage package trust.

The normal passkey path is:

```bash
node scripts/configure-npm-trusted-publishing.mjs
```

The script will print and open npm's passkey URL. After passkey confirmation,
it configures all 36 packages and ends with:

```text
Verified trusted publishing for 36 package(s).
```

After the trusted publisher entries are configured, token-based publish access
can be restricted from npm package settings.
