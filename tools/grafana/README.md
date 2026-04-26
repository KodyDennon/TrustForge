# TrustForge Grafana dashboards

This directory ships a complete observability stack for TrustForge:

- `dashboards/trustforge-overview.json` — top-level health: decisions/sec,
  deny rate, approval queue depth, p50/p95/p99 decide latency,
  revocations active, sessions open, plugins loaded by kind.
- `dashboards/trustforge-traces.json` — Tempo-backed trace explorer
  pre-filtered to TrustForge service spans (`tf.daemon.decide`,
  `tf.bridge.import_credential`, `tf.proof.sign`/`verify`,
  `tf.session.handshake`/`tick`, `tf.evidence.assemble`/`verify`)
  with span-attribute breakdowns by `tf.action`, `tf.decision`,
  `tf.actor_resolved`.
- `dashboards/trustforge-bridges.json` — per-bridge import-credential
  success/error rate; sniffer breakdown by `host_token_kind`.
- `dashboards/trustforge-evidence.json` — evidence pipeline
  (TF-0012 compliance evidence): bundles/sec, sealing latency,
  redactions, verification failures.
- `dashboards/trustforge-federation.json` — federation: trust-domain
  count, federation handshake errors, cross-domain decision count.

All dashboards are Grafana 10+ "Dashboard JSON model" exports and use
templating variables `service`, `instance`, `bridge_kind` (sourced from
Prometheus label values). Datasource UIDs are `prometheus` and `tempo`
to match `provisioning/datasources.yaml`.

## Metric names

The dashboards query the canonical metric names emitted by `tf-otel`
(crates/tf-otel) and the `tf-prom-exporter` binary
(tools/native/prometheus-exporter):

| Prometheus | OTLP | Description |
|------------|------|-------------|
| `tf_decisions_total` | `tf.decide.count` | Counter of finalized decides, labelled by `decision`/`method`/`actor`. |
| `tf_decisions_latency_seconds` | `tf.decide.latency` | Histogram of decide latency (seconds). |
| `tf_approval_queue_depth` | `tf.approval.queue_depth` | Gauge / up-down counter for pending approvals. |
| `tf_revocations_active` | `tf.revocation.active` | Gauge of currently active revocations. |
| `tf_sessions_open` | `tf.session.open` | Gauge of currently open sessions. |
| `tf_plugins_loaded` | (Prometheus only) | Gauge of plugins, labelled by `kind`. |
| `tf_proof_events_total` | `tf.proof_event.count` | Counter of proof events, labelled by `type`. |

Everything is exposed by either the Prometheus pull endpoint
(`tf-prom-exporter`) or the OTLP push channel (`tf-otel`'s
`init_otel("tf-...", Some(endpoint))`). The exporter ships both side by
side, so a single binary feeds Prometheus and OTLP collectors in
parallel.

## docker-compose snippet

The simplest way to bring up the stack locally:

```yaml
# docker-compose.yml
version: "3.9"
services:
  prometheus:
    image: prom/prometheus:v2.55.1
    ports: ["9090:9090"]
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro

  tempo:
    image: grafana/tempo:2.6.0
    command: ["-config.file=/etc/tempo/tempo.yaml"]
    ports:
      - "3200:3200"   # tempo HTTP
      - "4317:4317"   # OTLP gRPC
      - "4318:4318"   # OTLP HTTP
    volumes:
      - ./tempo.yaml:/etc/tempo/tempo.yaml:ro

  grafana:
    image: grafana/grafana:11.3.0
    ports: ["3000:3000"]
    depends_on: [prometheus, tempo]
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: "Editor"
    volumes:
      # Mount the provisioning files so Grafana auto-loads our
      # datasources and dashboard provider on startup.
      - ./tools/grafana/provisioning/datasources.yaml:/etc/grafana/provisioning/datasources/datasources.yaml:ro
      - ./tools/grafana/provisioning/dashboards.yaml:/etc/grafana/provisioning/dashboards/dashboards.yaml:ro
      - ./tools/grafana/dashboards:/var/lib/grafana/dashboards/trustforge:ro

  tf-prom-exporter:
    build: .
    command:
      - tf-prom-exporter
      - --bind=0.0.0.0:9464
      - --daemon-url=http://tf-daemon:8787
      - --otlp-endpoint=http://tempo:4317
    ports: ["9464:9464"]
```

## prometheus.yml snippet

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: tf-prom-exporter
    static_configs:
      - targets: ["tf-prom-exporter:9464"]
        labels:
          service: tf-daemon
  # If you also export OTLP metrics through an OTel collector that
  # exposes a Prometheus endpoint, scrape it here too:
  # - job_name: tf-otel-collector
  #   static_configs:
  #     - targets: ["otel-collector:8889"]
```

## Import flow (manual, without provisioning)

If you can't (or don't want to) run the auto-provisioning containers:

1. Open Grafana, go to **Connections -> Datasources**, add a Prometheus
   datasource pointing at your `tf-prom-exporter` scraper. Optionally add
   a Tempo datasource pointing at the OTLP collector endpoint.
2. Go to **Dashboards -> New -> Import**, then for each JSON file under
   `tools/grafana/dashboards/`:
   - Paste the JSON or upload the file.
   - Pick the Prometheus datasource you just created when prompted.
   - For `trustforge-traces.json`, additionally pick the Tempo datasource.
3. Use the `service` / `instance` / `bridge_kind` template variables at
   the top of each dashboard to scope to a specific deployment.

## Wiring `tf-otel` into your binary

```rust
let otel = tf_otel::init_otel("tf-myservice", Some("http://localhost:4317"))?;
otel.install_subscriber()?;       // tracing -> OTel bridge
let metrics = otel.metrics();     // canonical instrument set
tf_otel::record_decide(metrics, "allow", "GET /v1/decide",
    "tf:actor:user:test", Some("https://example.com/path"), 0.0042);
// ...
otel.shutdown();                  // flush before exit
```

The same instrument names appear in the dashboards above unchanged, so
any binary that uses `tf-otel` is automatically observable through this
suite.
