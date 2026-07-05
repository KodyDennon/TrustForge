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
NPM_TOKEN=... NPM_OTP=123456 \
  node scripts/configure-npm-trusted-publishing.mjs
```

The script discovers the root package plus all npm workspaces and configures:

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

## Auth Requirements

The npm trust API requires:

- an npm token with write access to each package
- npm 2FA enabled on the account
- a current `NPM_OTP` one-time password for trust API reads and writes

The script reads `NPM_TOKEN` from the environment first. If omitted, it can use
a token already present in `.npmrc` or `~/.npmrc`. It never prints the token or
OTP.

After the trusted publisher entries are configured, token-based publish access
can be restricted from npm package settings.
