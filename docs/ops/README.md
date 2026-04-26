# Operations

This directory is the operator-facing handbook. Use these pages
when you are installing, configuring, monitoring, upgrading, or
recovering a TrustForge deployment. They complement, but do not
replace, the spec ([`../specs/`](../specs/)) and the architecture
docs ([`../architecture/`](../architecture/)).

The audience is whoever is on call when the daemon misbehaves.

## What lives here

| Document | Use when |
|---|---|
| [`installation.md`](installation.md) | Installing TrustForge on Linux, macOS, Windows, in a container, or on an embedded target. |
| [`configuration.md`](configuration.md) | Picking flags, env vars, and YAML knobs. |
| [`runbook-incident.md`](runbook-incident.md) | An incident is in progress and you need step-by-step responses. |
| [`observability.md`](observability.md) | Wiring Prometheus, OTLP, dashboards, log levels. |
| [`upgrade.md`](upgrade.md) | Moving between TrustForge versions. |
| [`disaster-recovery.md`](disaster-recovery.md) | Backups, restoration, federation recovery after a catastrophic loss. |

## Reading order

If you are new to running TrustForge:

1. [`installation.md`](installation.md) — pick a target.
2. [`configuration.md`](configuration.md) — minimal config that
   actually boots, then bolt on profile and federation.
3. [`observability.md`](observability.md) — wire metrics and logs
   before you take real traffic.
4. [`upgrade.md`](upgrade.md) — read this before your first patch
   release; the policy is "don't skip versions".
5. [`disaster-recovery.md`](disaster-recovery.md) — print this.
   Test the restore. Print it again.
6. [`runbook-incident.md`](runbook-incident.md) — keep open during
   an incident.

## Key files an operator interacts with

```
.tf/
  daemon.yaml          # daemon config
  policy.yaml          # policy bundle (Cedar / Rego rules)
  agent-contract.yaml  # AI-agent contract (if applicable)
  threat-model.yaml    # deployment-specific threat model
  profile.yaml         # asserted profile (refused at boot if MUSTs unmet)
  vault.tfvault        # sealed long-term keys
  ledger.db            # SQLite ledger (or Postgres URL in daemon.yaml)
```

Every one of these is documented, schema-validated, and referenced
from the same doc. See [`configuration.md`](configuration.md).

## Daemon surfaces an operator should know

```mermaid
flowchart LR
    subgraph daemon["tf-daemon"]
        admin[/v1/decide<br>/v1/proof/sign<br>/v1/proof/verify<br>/v1/import-credential]
        sess[Session listener<br>WebSocket / TCP / TLS]
        bin[Binary path<br>TF-0013 TLS]
        met[/metrics<br>Prometheus]
        otlp[OTLP traces<br>egress]
        admin --> bin
        sess --> bin
    end
    Op[Operator] --> admin
    App[App] --> admin
    Peer[Peer daemon] --> sess
    Promscrape[Prometheus] --> met
    Tempo[Tempo / Jaeger] <-- otlp
```

- **`/admin`** — the operator/adapter HTTP surface. Loopback or
  UDS in single-host; LAN or mTLS for multi-host.
- **`session listener`** — Live-mode handshake carriers (WebSocket
  in TS, TCP in Rust). Default port 8788.
- **`binary path`** — TF-0013 site-to-site listener. Default port
  8443.
- **`/metrics`** — Prometheus scrape. Default port 9090 (separate
  listener, not on the admin endpoint).
- **OTLP** — outbound traces to a collector.

Each is configurable. None must be exposed to the public internet
unless your topology explicitly needs it.

## Profiles vs. environments

A *profile* (see [`../profiles/`](../profiles/)) is the
conformance label the daemon claims at boot:

- `tf-home-compatible` — single-operator deployments.
- `tf-enterprise-compatible` — multi-tenant with federation and
  transparency anchoring.
- `tf-constrained-compatible` — LoRa, BLE, sneakernet.
- `tf-compliance-evidence-compatible` — legal/compliance evidence
  with offline reproducibility.

The daemon refuses to boot if the asserted profile's MUST features
are not satisfied (e.g. `tf-compliance-evidence-compatible`
requires an RFC 3161 anchor; if none is configured, boot fails
with a useful error).

An *environment* is your business label (`prod-eu`, `staging`,
`lab-13`). Profiles and environments are orthogonal; mark both in
`daemon.yaml`.

## Where the docs assume you are

These pages assume:

- You have read the
  [`../tutorials/01-getting-started.md`](../tutorials/01-getting-started.md)
  tutorial and have a daemon booting locally.
- You have skimmed the architecture
  [`system-overview.md`](../architecture/system-overview.md).
- You have permission to read
  [`../security/key-handling.md`](../security/key-handling.md)
  before touching long-term keys.

If you have not, start there.

## Status

Draft. The flag and env-var lists in
[`configuration.md`](configuration.md) reflect the 0.1.0
implementation in `tools/tf-daemon/` and `tools/tf-cli/`. Always
cross-check against `--help` output for the version you are
running.
