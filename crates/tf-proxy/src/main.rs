//! tf-proxy binary entry point.
//!
//! Parses CLI arguments, builds a [`ProxyConfig`], and runs the proxy server.

use std::net::SocketAddr;

use clap::Parser;
use tf_proxy::{run, Mode, ProxyConfig, ProxyState};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "tf-proxy",
    version,
    about = "TrustForge enforcement reverse proxy"
)]
struct Cli {
    /// Address to listen on for client connections.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    /// Upstream service URL (required).
    #[arg(long)]
    upstream: String,

    /// tf-daemon base URL.
    #[arg(long, default_value = "http://127.0.0.1:8642")]
    daemon: String,

    /// Admin token to forward to tf-daemon (env: TF_ADMIN_TOKEN).
    #[arg(long, env = "TF_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// Profile name to advertise in proof events.
    #[arg(long, default_value = "tf-home-compatible")]
    profile: String,

    /// Mode: `observe-only` or `enforce`.
    #[arg(long, default_value = "observe-only")]
    mode: Mode,

    /// Path to the TLS certificate (PEM). Requires --tls-key.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to the TLS private key (PEM). Requires --tls-cert.
    #[arg(long)]
    tls_key: Option<String>,

    /// Optional OTLP gRPC endpoint (e.g. http://localhost:4317). Falls
    /// back to OTEL_EXPORTER_OTLP_ENDPOINT; if neither is set, the SDK
    /// is brought up with a stdout exporter.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Install a default crypto provider for rustls (needed by tokio-rustls
    // and reqwest's rustls backend).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // Bring up OpenTelemetry first so the tracing subscriber we install
    // below can attach the OTel bridge layer. We deliberately set the
    // global default ourselves rather than calling
    // `handle.install_subscriber()` so the daemon's existing fmt layer
    // (line-oriented logs to stderr) and the OTel layer coexist.
    let otel = tf_otel::init_otel("tf-proxy", cli.otlp_endpoint.as_deref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("otel init: {e}")))?;
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tf_proxy=info"));
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel.tracing_layer());
    let _ = tracing::subscriber::set_global_default(subscriber);

    let cfg = ProxyConfig {
        listen: cli.listen,
        upstream: cli.upstream,
        daemon: cli.daemon,
        admin_token: cli.admin_token,
        profile: cli.profile,
        mode: cli.mode,
        tls_cert: cli.tls_cert,
        tls_key: cli.tls_key,
    };
    let state = ProxyState::new(cfg);
    state.set_otel(otel.clone());
    let result = run(state).await;
    // Best-effort flush of pending spans/metrics before exit.
    otel.shutdown();
    result
}
