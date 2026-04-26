# Observability

How TrustForge exposes its internal state for monitoring and
debugging. Three channels: Prometheus metrics, OpenTelemetry
traces, and structured logs.

A reference Grafana dashboard lives under
[`../../tools/grafana/`](../../tools/grafana/) when present
(grafana JSON files are added as the operator-side tooling
matures). The dashboard depends on the metrics described below;
if you wire your own dashboard, the metric names below are stable
across the 0.1.x line.

## Channels at a glance

```mermaid
flowchart LR
    subgraph daemon["tf-daemon"]
        m[/metrics<br/>Prometheus]
        t[OTLP traces<br/>egress]
        l[stdout / journald<br/>structured logs]
    end
    P[Prometheus] -- scrape --> m
    G[Grafana] --> P
    OTel[OTLP collector<br/>e.g. otel-collector] <-- t
    Tempo[Tempo / Jaeger] <-- OTel
    Loki[Loki / journald] <-- l
    Alert[Alertmanager] <-- P
    Dash[tf-dashboard]
    Dash --> daemon
```

The viewer-only [`tools/tf-dashboard/`](../../tools/tf-dashboard/)
is *not* an observability backend; it reads the daemon admin
endpoint. Use it for human inspection of pending approvals, recent
proof events, and active sessions, not for alerting.

## Prometheus metrics

Default endpoint: `127.0.0.1:9090/metrics`. Override with
`TF_LISTEN_METRICS` or `listen.metrics` in `daemon.yaml`.

### Counters

| Metric | Labels | Meaning |
|---|---|---|
| `tf_decisions_total` | `decision`, `profile` | Total `/v1/decide` evaluations. `decision` is `allow|deny|escalate|approve|log|constrain`. |
| `tf_proof_events_total` | `kind`, `level` | Proof events emitted; `kind` is the event kind, `level` is L0–L5. |
| `tf_packets_total` | `direction`, `outcome` | Packets handled; `direction` is `tx|rx`, `outcome` is `accepted|rejected|forwarded`. |
| `tf_session_events_total` | `event` | Session lifecycle events (`opened`, `rekeyed`, `closed`). |
| `tf_approvals_total` | `outcome` | Approvals processed (`granted`, `denied`, `expired`). |
| `tf_bridge_credentials_total` | `bridge`, `outcome` | Imported credentials (`spiffe`, `oauth`, `webauthn`, `tls`, `did`, `matrix`, `webhook`). |
| `tf_revocations_total` | `actor_kind` | Revocations issued. |
| `tf_anchor_inclusions_total` | `anchor` | Successful anchor inclusion proofs (`rfc6962`, `rfc3161`). |
| `tf_replay_rejections_total` | `cause` | Packet/frame replay rejections; `cause` is `nonce_seen|time_skew|window_expired`. |

### Gauges

| Metric | Labels | Meaning |
|---|---|---|
| `tf_active_sessions` | — | Live-mode sessions currently open. |
| `tf_pending_approvals` | — | Approvals waiting in the queue. |
| `tf_federated_peers` | `status` | Peers, by `status` (`acknowledged`, `rotation_pending`, `revoked`). |
| `tf_vault_unlocked` | — | 1 if the vault is unlocked, 0 otherwise. |
| `tf_clock_skew_seconds` | `peer` | Estimated skew vs. each peer or anchor. |

### Histograms

| Metric | Buckets | Meaning |
|---|---|---|
| `tf_decision_duration_seconds` | 1ms…1s | `/v1/decide` end-to-end. |
| `tf_proof_sign_duration_seconds` | 1ms…100ms | `/v1/proof/sign` time. |
| `tf_session_handshake_duration_seconds` | 10ms…2s | TF-0003 handshake completion time. |
| `tf_anchor_round_trip_seconds` | 50ms…5s | Round-trip to RFC 6962 / RFC 3161 anchor. |

### Recommended alerts

A starter set, matching the threat-model risk classes:

- **R5**: `tf_vault_unlocked == 0` for more than 60s (vault locked
  unexpectedly).
- **R5**: `rate(tf_replay_rejections_total{cause="nonce_seen"}[5m]) > 0.1`
  (sustained nonce replay).
- **R4**: `tf_federated_peers{status="rotation_pending"} > 0` for
  more than 1 hour (a peer rotated and we have not acknowledged).
- **R4**: `rate(tf_decisions_total{decision="deny"}[5m]) /
  rate(tf_decisions_total[5m]) > 0.5` (deny ratio surge —
  indicative of misconfiguration or attack).
- **R3**: `histogram_quantile(0.99,
  rate(tf_decision_duration_seconds_bucket[5m])) > 0.1` (decision
  p99 over 100ms — investigate policy regression).
- **R2**: `tf_anchor_round_trip_seconds` p99 > 5s (anchor service
  degraded; not blocking but worth tracking).

## OpenTelemetry traces

The daemon emits OTLP traces when `TF_OTLP_ENDPOINT` (or
`tracing.otlp_endpoint` in YAML) is set. Spans include:

- `tf.decide` — one span per `/v1/decide` call. Attributes:
  `actor.uri`, `action`, `target`, `decision`, `policy.engine`.
- `tf.proof.sign` and `tf.proof.verify` — one span per call.
  Attributes: `event.kind`, `level`, `chain.index`.
- `tf.session.handshake` — one span per handshake. Attributes:
  `peer.uri`, `transport`, `suite`.
- `tf.bridge.import` — one span per credential import. Attributes:
  `bridge.kind`, `outcome`.
- `tf.rpc.call` — one span per ProofRPC call. Attributes:
  `method.name`, `method.kind`.

Trace context propagation: TrustForge propagates W3C `traceparent`
on session frames and admin HTTP requests. ProofRPC frames carry
`trace_id` and `span_id` fields; downstream services see the
parent span automatically.

## Structured logs

Set `TF_LOG_FORMAT=json` for machine-friendly output; the default
is human-readable text. Each log line contains:

- `timestamp` — RFC 3339 with monotonic-anchored wall clock.
- `level` — `error|warn|info|debug|trace`.
- `target` — the module emitting the log.
- `event` — short identifier (e.g. `proof.event.appended`).
- `actor` — the calling actor URI when known.
- `decision` — when applicable.
- `latency_ms` — for request-driven events.
- `request_id` — correlation across logs and traces.
- `trace_id`, `span_id` — when tracing is enabled.

Set `TF_LOG=debug` for development; default `info` is
production-safe (no sensitive payloads logged at `info`).

Sensitive data the daemon never logs:

- Vault passphrases.
- AEAD plaintext.
- Capability tokens (only token IDs and audiences are logged).
- Private keys.
- Bridged credentials beyond the kind and outcome.

## tf-dashboard

`tools/tf-dashboard/` is a viewer-only HTML dashboard reading the
admin endpoint. It is **not** an observability backend; do not
build alerts on it. Use it to:

- See active sessions.
- Review pending approvals before granting / denying via the CLI.
- Inspect recent proof events.
- Confirm federation peer state.

The dashboard requires the same admin token as the CLI; serve it
on loopback only.

## Health endpoints

```
GET /v1/health                  Daemon liveness (200 if running).
GET /v1/health/ready            Readiness (200 if vault unlocked,
                                ledger reachable, profile MUSTs satisfied).
GET /v1/health/profile          Returns the asserted profile and
                                the satisfaction status of every MUST.
```

These are unauthenticated by default but bind only to loopback.
For multi-host deployments, expose them via a dedicated
network-policy-restricted listener.

## Log levels by surface

| Surface | Default level | Notes |
|---|---|---|
| Admin HTTP request handling | `info` | Logs request, decision, latency. |
| Session protocol | `info` for lifecycle, `debug` for frames. |
| Policy engine | `info` for decisions, `debug` for rule traces. |
| Bridges | `info` for imports, `debug` for parser traces. |
| Anchors | `info` for inclusion success, `warn` for retry. |
| Plugins | `info` for load/unload, `warn` for sandbox violations. |

Bumping a single subsystem's log level requires `SIGHUP` reload
(see [`configuration.md`](configuration.md)).

## Capacity planning signals

Watch for:

- `tf_active_sessions` approaching your file-descriptor limit.
- `tf_pending_approvals` growing — operators not keeping up.
- `tf_decision_duration_seconds` p99 trending up — policy bundle
  is getting too complex.
- `tf_anchor_round_trip_seconds` p99 trending up — anchor service
  saturation.
- `tf_clock_skew_seconds` exceeding 30s — NTP regression.

## Sample Prometheus scrape config

```yaml
scrape_configs:
  - job_name: trustforge
    static_configs:
      - targets: ['daemon-h1:9090', 'daemon-h2:9090']
        labels:
          environment: 'prod-eu'
          profile: 'tf-enterprise-compatible'
```

## Sample OTLP exporter config

```yaml
# in daemon.yaml
tracing:
  otlp_endpoint: "http://otel-collector.internal:4318"
  service_name: "trustforge-prod-eu"
  sample_ratio: 0.1
```

Sampling lower than 1.0 still captures every `error`-level span;
the daemon ignores sampling for spans that emit a proof event.

## Tying it back to the spec

The metrics and trace attributes named here are stable across the
0.1.x line. They are exercised by the conformance suite under
`tools/tf-conformance/` (the `observability` category, planned
for v0.2 — in 0.1.0 the metrics are stable but not yet in the
conformance contract). When v0.2 lands, this page will be updated
to point at the conformance vector.
