# Configuration

Every CLI flag, every environment variable, every `.tf/*.yaml`
file the daemon reads. The authoritative source is the daemon's
`--help` output and the schemas under
[`../../schemas/`](../../schemas/); this page summarises and
cross-references them.

## Configuration sources, in precedence order

1. **CLI flags** to `tf-daemon run` and `tf …` subcommands.
2. **Environment variables** with `TF_` prefix.
3. **`.tf/daemon.yaml`** (path overridable with `--config`).
4. **`.tf/profile.yaml`** (asserted profile).
5. **Built-in defaults**.

A flag overrides an env var; an env var overrides a YAML value;
a YAML value overrides a built-in default. The daemon prints the
effective configuration at startup with secret values redacted.

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `TF_VAULT_PASS` | Yes for any command that touches the vault | none | Argon2id input; do not log. Prefer secret-store integration in production. |
| `TF_ADMIN_TOKEN` | Yes for the daemon | none | Bearer token for the admin HTTP endpoint. Generate with `openssl rand -hex 16`. |
| `TF_OTLP_ENDPOINT` | No | (unset) | Outbound OTLP traces endpoint. |

Secrets that should never be set on the command line:
`TF_VAULT_PASS`, `TF_ADMIN_TOKEN`. Use `EnvironmentFile=` with
mode `0600`, or a secret-store integration.

## CLI flags (daemon)

`tf-daemon run` currently accepts:

```
--config <PATH>             Path to daemon.yaml.
--dry-run                   Validate config and exit.
--print-config              Print effective config (secrets redacted) and exit.
```

`tf` (the unified CLI in `tools/tf-cli/`) has many subcommands; run
`tf --help` for the canonical list. The 0.1.0 surface is:

```
tf actor create | inspect | rotate | revoke
tf trust-domain init | federate | verify-federation
tf bridge spiffe import | webauthn import | oauth import | ...
tf packet sign | verify | inspect | fragment | reassemble
tf session inspect
tf approval list | approve | deny
tf revoke <kind> <id>
tf plugin list
tf rpc call
tf evidence assemble | verify | seal | open | replay | redact
tf conformance run
tf policy simulate
tf generate <policy|mcp-tool-wrapper|audit-viewer|bridge|proofrpc-service>
```

## `.tf/daemon.yaml`

The schema is [`../../schemas/daemon-config.schema.json`](../../schemas/daemon-config.schema.json).
A practical Linux v0.2-style example:

```yaml
daemon_version: "1"
self_actor: "tf:actor:service:example.com/tf-daemon"
listen:
  kind: websocket
  bind: "127.0.0.1"
  port: 8788
vault:
  path: "/var/lib/trustforge/vault.tfvault"
contract_path: "/etc/trustforge/agent-contract.yaml"
proof_log_path: "/var/lib/trustforge/proof.tflog"
profile: "tf-home-compatible"
http:
  tcp:
    enabled: true
    bind: "127.0.0.1"
    port: 8642
    auth: bearer
  unix:
    enabled: true
    path: "/run/trustforge/decide.sock"
    auth: local-peer
admin:
  enabled: true
  token_env: TF_ADMIN_TOKEN
  bind: "127.0.0.1"
  revocation_path: "/var/lib/trustforge/revocations.json"
```

## `.tf/policy.yaml`

The policy bundle. Schema: `schemas/policy-bundle.schema.json`.
Two engines are supported: Cedar (`crates/tf-cedar/`) and Rego
(`crates/tf-rego/`). Both produce the same `Decision` shape.

A minimal Cedar bundle:

```yaml
engine: cedar
schema: |
  entity Action;
  entity Actor;
  entity Target;
rules: |
  permit (
    principal,
    action == Action::"http.read",
    resource
  ) when {
    principal.trust_level >= 3
  };
```

See [`../tutorials/04-policy-authoring.md`](../tutorials/04-policy-authoring.md)
for a worked example.

## `.tf/agent-contract.yaml`

The AI-agent contract. Schema:
`schemas/agent-contract.schema.json`. This file is mandatory for
deployments that host AI agents. See
[`../ai-implementation.md`](../ai-implementation.md) and the
example at [`../../examples/agent-contracts/full.yaml`](../../examples/agent-contracts/full.yaml).

## `.tf/threat-model.yaml`

The deployment threat model. Schema:
`schemas/threat-model.schema.json`. The repo's own threat model
sits at [`../../.tf/threat-model.yaml`](../../.tf/threat-model.yaml)
and is documented in
[`../security/threat-model.md`](../security/threat-model.md).

## `.tf/profile.yaml`

The asserted conformance profile. Either:

```yaml
profile: "tf-home-compatible"
```

or a per-feature override that still passes the profile's MUST set:

```yaml
profile:
  base: "tf-enterprise-compatible"
  override:
    must_features:
      - rfc6962-anchor
      - federation-attestation-pin
```

The daemon runs profile assertion at boot; if any MUST feature is
unsatisfied, it logs the failing feature and exits non-zero.

## Listener defaults and what they mean

| Listener | Default bind | Auth mode |
|---|---|---|
| Session WS / TCP | `listen.bind` + `listen.port` | Session handshake. |
| v1 TCP HTTP | `127.0.0.1:8642` | Bearer token. |
| v1 Unix socket | `/run/trustforge/decide.sock` | Local peer/filesystem trust for `/v1/decide`; bearer for privileged routes. |
| Admin HTTP | Same Bun listener as session HTTP upgrade path | Bearer token + Host check. |

Bind any listener to `0.0.0.0` only when your topology requires it.
The admin endpoint should never be public. TCP `/v1/*` stays bearer
protected; Linux local integrations should use the Unix socket.

## Secret-store integrations

Setting `TF_VAULT_PASS` and `TF_ADMIN_TOKEN` directly is fine for
development. For production:

- **Linux**: `systemd-creds` for both, or HashiCorp Vault via
  `vault agent template`.
- **macOS**: Keychain access via a small wrapper script.
- **Kubernetes**: a `Secret` mounted as files, with
  `EnvironmentFile=/run/secrets/tf-env` style loading.
- **Cloud**: AWS Secrets Manager / GCP Secret Manager / Azure Key
  Vault, fetched at boot by a sidecar that writes the env file.

The daemon does not fetch from secret stores itself; that is the
operator's job (this is intentional — fewer SDKs in the daemon's
trust boundary).

## Validating a config without booting

```bash
tf-daemon run --config .tf/daemon.yaml --dry-run
```

Validates the daemon config shape, referenced paths, and asserted
profile name, then exits without opening listeners or unlocking the
vault. Use this in CI before a deploy.

## Printing the effective config

```bash
tf-daemon run --config .tf/daemon.yaml --print-config
```

Prints the effective config with secrets redacted. Useful
when debugging precedence (was that env var actually picked up?).

## Reload behaviour

The daemon does not hot-reload `daemon.yaml`. To change config:

1. Update the YAML.
2. Send `SIGHUP` for changes that the daemon supports reloading
   (logging level, policy bundle, peer bundles).
3. Restart the daemon for everything else (listeners, ledger
   backend, profile).

`SIGHUP`-reloadable surfaces are:

- `policy.bundle` — re-read and recompiled.
- `federation.peers` — bundles re-read.
- `logging.level` — re-applied immediately.

A planned `tf admin reload` command will provide a more
fine-grained interface in v0.2.
