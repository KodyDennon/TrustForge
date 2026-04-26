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
| `TF_CONFIG` | No | `.tf/daemon.yaml` | Path to the YAML config. Same as `--config`. |
| `TF_PROFILE` | No | value from `daemon.yaml` | Override the asserted profile. |
| `TF_LOG` | No | `info` | One of `error`, `warn`, `info`, `debug`, `trace`. |
| `TF_LOG_FORMAT` | No | `text` | `text` or `json`. |
| `TF_LISTEN_ADMIN` | No | `127.0.0.1:8787` | Override the admin listener. |
| `TF_LISTEN_SESSION` | No | `127.0.0.1:8788` | Override the session listener. |
| `TF_LISTEN_BINARY_PATH` | No | (unset) | TF-0013 binary-path listener bind address. Unset = disabled. |
| `TF_LISTEN_METRICS` | No | `127.0.0.1:9090` | Prometheus listener. |
| `TF_LEDGER_URL` | No | from YAML | Override the ledger backend URL. |
| `TF_REVOCATION_URL` | No | from YAML | Override the Redis revocation URL. |
| `TF_ANCHOR_URL` | No | from YAML | RFC 6962 / RFC 3161 anchor service. |
| `TF_OTLP_ENDPOINT` | No | (unset) | Outbound OTLP traces endpoint. |
| `TF_NETWORK_ALLOW` | No | (loopback) | Comma-separated CIDRs the admin endpoint will accept. |

Secrets that should never be set on the command line:
`TF_VAULT_PASS`, `TF_ADMIN_TOKEN`. Use `EnvironmentFile=` with
mode `0600`, or a secret-store integration.

## CLI flags (daemon)

`tf-daemon run` accepts:

```
--config <PATH>             Path to daemon.yaml.
--profile <ID>              Override asserted profile.
--listen-admin <ADDR>       Bind admin endpoint.
--listen-session <ADDR>     Bind session listener.
--listen-binary-path <ADDR> Bind TF-0013 binary path listener.
--listen-metrics <ADDR>     Bind Prometheus listener.
--ledger-url <URL>          sqlite:..., postgres://..., mysql://...
--revocation-url <URL>      redis://...
--otlp <URL>                Outbound OTLP endpoint.
--log <LEVEL>               error|warn|info|debug|trace
--log-format <FMT>          text|json
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

The full schema is `schemas/daemon-config.schema.json` (planned name;
the runtime parser is in `tools/tf-daemon/src/config/`). A
fully-populated example:

```yaml
listen:
  admin: "127.0.0.1:8787"
  session: "127.0.0.1:8788"
  binary_path:
    bind: "0.0.0.0:8443"
    tls:
      cert: "/etc/trustforge/certs/site.crt"
      key:  "/etc/trustforge/certs/site.key"
  metrics: "127.0.0.1:9090"

profile: "tf-enterprise-compatible"

vault:
  path: "/var/lib/trustforge/vault.tfvault"
  argon2:
    memory_kib: 65536
    iterations: 3
    parallelism: 1

ledger:
  backend: "postgres"        # or "sqlite", "mysql"
  url: "postgres://tf:…@db/tf_ledger"

revocation:
  backend: "redis"           # or "in-memory"
  url: "redis://redis:6379/0"

federation:
  peers:
    - bundle: "/etc/trustforge/peer-bundles/b.example.bundle"

anchors:
  rfc6962:
    enabled: true
    log_url: "https://ct.example.com"
  rfc3161:
    enabled: false
    tsa_url: "https://tsa.example.com"

policy:
  engine: "cedar"            # or "rego"
  bundle: ".tf/policy.yaml"

agent_contract: ".tf/agent-contract.yaml"

logging:
  level: "info"
  format: "json"

tracing:
  otlp_endpoint: "https://tempo.internal:4318"
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

| Listener | Default bind | Defaults to public? |
|---|---|---|
| Admin HTTP | `127.0.0.1:8787` | No. |
| Session WS / TCP | `127.0.0.1:8788` | No. |
| Binary path (TF-0013) | (disabled unless configured) | When configured, typically `0.0.0.0:8443`. |
| Metrics | `127.0.0.1:9090` | No. |

Bind any "yes" listener to `0.0.0.0` only when your topology
requires it. The admin endpoint should never be public; the
session listener may be public for federation; the binary path is
public-by-design (it is your WAN listener).

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

Validates schema, asserts profile MUST features, exits non-zero on
failure with a descriptive error. Use this in CI before a deploy.

## Printing the effective config

```bash
tf-daemon run --config .tf/daemon.yaml --print-config
```

Prints the merged config with secrets redacted (`***`). Useful
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
