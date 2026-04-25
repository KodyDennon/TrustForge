//! tf-proxy binary entry point.
//!
//! Parses CLI arguments, builds a [`ProxyConfig`], and runs the proxy server.

use std::net::SocketAddr;

use clap::Parser;
use tf_proxy::{Mode, ProxyConfig, ProxyState, run};
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
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tf_proxy=info")),
        )
        .try_init();

    // Install a default crypto provider for rustls (needed by tokio-rustls
    // and reqwest's rustls backend).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
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
    run(state).await
}
