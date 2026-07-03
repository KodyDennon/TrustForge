//! tf-prom-exporter — TrustForge Prometheus exporter binary.

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tf_prom_exporter::{scrape_once, serve_metrics, Metrics, ScrapeConfig, ScrapeState};

#[derive(Parser, Debug)]
#[command(name = "tf-prom-exporter", version, about)]
struct Args {
    /// Bind address for the exporter's /metrics endpoint.
    #[arg(long, default_value = "127.0.0.1:9090")]
    bind: SocketAddr,

    /// tf-daemon admin URL (must speak the /admin/* HTTP API).
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    daemon_url: String,

    /// Bearer token for /admin/*. Falls back to TF_ADMIN_TOKEN.
    #[arg(long)]
    admin_token: Option<String>,

    /// Polling interval, in seconds.
    #[arg(long, default_value_t = 10)]
    interval_seconds: u64,

    /// HTTP timeout for daemon scrapes, in seconds.
    #[arg(long, default_value_t = 5)]
    timeout_seconds: u64,

    /// Optional OTLP gRPC endpoint. When set the exporter mirrors every
    /// scrape into the canonical `tf.*` OTel instruments in addition to
    /// the Prometheus text format. Defaults to OTEL_EXPORTER_OTLP_ENDPOINT.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Bring up OTel side channel. If neither --otlp-endpoint nor the env
    // var is set, init_otel installs a stdout exporter so dev runs still
    // see the canonical `tf.*` metrics.
    let otel = tf_otel::init_otel("tf-prom-exporter", args.otlp_endpoint.as_deref())
        .map_err(|e| std::io::Error::other(format!("otel init: {e}")))?;

    let metrics = Arc::new(Metrics::new().with_otel(Some(otel.clone())));
    let mut cfg = ScrapeConfig::new(args.daemon_url.clone());
    if let Some(t) = args.admin_token.clone() {
        cfg.admin_token = Some(t);
    }
    cfg.timeout = Duration::from_secs(args.timeout_seconds);

    let serve = serve_metrics(args.bind, metrics.clone()).await?;
    tracing::info!(
        bind = %serve.local,
        daemon = %cfg.daemon_url,
        "tf-prom-exporter listening"
    );

    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .build()
        .expect("build reqwest client");
    let mut state = ScrapeState::default();
    let mut tick = tokio::time::interval(Duration::from_secs(args.interval_seconds));

    let metrics_for_loop = metrics.clone();
    let cfg_for_loop = cfg.clone();
    let scrape_loop = tokio::spawn(async move {
        loop {
            tick.tick().await;
            if let Err(e) = scrape_once(&cfg_for_loop, &metrics_for_loop, &mut state, &client).await
            {
                tracing::warn!(error = %e, "scrape failed");
            }
        }
    });

    // Wait until the user kills us. The serve handle holds the listening
    // socket; the scrape loop holds the polling task. Either ending stops us.
    let _ = scrape_loop.await;
    serve.stop().await;
    otel.shutdown();
    Ok(())
}
