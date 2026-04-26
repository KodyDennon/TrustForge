//! tf-proxy: TrustForge enforcement reverse proxy.
//!
//! Sits in front of an upstream HTTP/HTTPS service. For every request it
//! consults `tf-daemon`'s `/v1/decide` endpoint and either forwards, denies,
//! or surfaces an approval-required handoff based on the daemon's verdict.
//!
//! This crate is structured as a library so that the binary entry point in
//! `src/main.rs` is a thin wrapper and the proxy logic can be exercised by
//! integration tests.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::io::BufReader;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Operating mode for the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Always forward upstream, but still consult and log the daemon decision.
    ObserveOnly,
    /// Honour the daemon decision: deny becomes 403, approval becomes 202.
    Enforce,
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "observe-only" | "observe_only" | "observe" => Ok(Mode::ObserveOnly),
            "enforce" => Ok(Mode::Enforce),
            other => Err(format!("unknown mode: {other}")),
        }
    }
}

/// Runtime configuration for the proxy server.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: String,
    pub daemon: String,
    pub admin_token: Option<String>,
    pub profile: String,
    pub mode: Mode,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

/// Decide-request body sent to tf-daemon.
#[derive(Serialize, Debug)]
pub struct DecideRequest<'a> {
    pub actor: Option<&'a str>,
    pub host_token: Option<String>,
    pub host_token_kind: Option<String>,
    pub action: String,
    pub target: String,
    pub context: serde_json::Value,
    pub trace_id: String,
}

/// Decide-response body returned by tf-daemon.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct DecideResponse {
    pub decision: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub proof_id: Option<String>,
    #[serde(default)]
    pub approval_id: Option<String>,
}

/// Shared state used by every connection handler.
pub struct ProxyState {
    pub config: ProxyConfig,
    pub http: reqwest::Client,
    counter: AtomicU64,
    /// OpenTelemetry handle owned by the binary entry point. Set once at
    /// startup via [`ProxyState::set_otel`]. We use `OnceLock` so the
    /// `Arc<ProxyState>` we hand to connection tasks does not need to be
    /// rebuilt after wiring telemetry.
    otel: std::sync::OnceLock<tf_otel::TfOtelHandle>,
}

impl ProxyState {
    pub fn new(config: ProxyConfig) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        Arc::new(Self {
            config,
            http,
            counter: AtomicU64::new(0),
            otel: std::sync::OnceLock::new(),
        })
    }

    /// Install the process-wide OpenTelemetry handle. Should be called
    /// at most once during startup, before [`run`] handles any traffic.
    /// Uses `OnceLock` so this works through an `Arc<Self>`.
    pub fn set_otel(&self, handle: tf_otel::TfOtelHandle) {
        let _ = self.otel.set(handle);
    }

    /// Borrow the OTel handle, if one was installed.
    pub fn otel(&self) -> Option<&tf_otel::TfOtelHandle> {
        self.otel.get()
    }

    fn next_trace_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("tf-proxy-{nanos}-{n}")
    }
}

/// Pull a host token out of either an `Authorization: Bearer ...` header or a
/// session cookie. Returns the token plus a heuristic kind: `"jwt"` if it
/// looks like a JWT (three dot-separated segments), otherwise `"opaque"`.
pub fn extract_host_token(headers: &hyper::HeaderMap) -> Option<(String, String)> {
    if let Some(v) = headers.get(hyper::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(rest) = s.strip_prefix("Bearer ") {
                let token = rest.trim().to_string();
                if !token.is_empty() {
                    let kind = classify_token(&token);
                    return Some((token, kind));
                }
            }
        }
    }
    if let Some(v) = headers.get(hyper::header::COOKIE) {
        if let Ok(s) = v.to_str() {
            for raw in s.split(';') {
                let part = raw.trim();
                for name in ["__session=", "__Secure-next-auth.session-token="] {
                    if let Some(val) = part.strip_prefix(name) {
                        let token = val.trim().to_string();
                        if !token.is_empty() {
                            let kind = classify_token(&token);
                            return Some((token, kind));
                        }
                    }
                }
            }
        }
    }
    None
}

fn classify_token(t: &str) -> String {
    let dots = t.bytes().filter(|b| *b == b'.').count();
    if dots == 2
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        "jwt".to_string()
    } else {
        "opaque".to_string()
    }
}

/// Build the `action` string for a request. We split on `/`, drop empty
/// segments, lowercase the method, and join with `.`.
pub fn action_for(method: &Method, path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let m = method.as_str().to_ascii_lowercase();
    if segments.is_empty() {
        format!("{m}.root")
    } else {
        format!("{m}.{}", segments.join("."))
    }
}

/// Detect a websocket upgrade request.
pub fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Call tf-daemon's `/v1/decide`. Returns `Err` when the daemon is
/// unreachable or returns a malformed body.
pub async fn call_decide(
    state: &ProxyState,
    req_headers: &hyper::HeaderMap,
    method: &Method,
    path: &str,
    client_addr: SocketAddr,
    is_connect: bool,
) -> Result<DecideResponse, String> {
    let (token, kind) = match extract_host_token(req_headers) {
        Some((t, k)) => (Some(t), Some(k)),
        None => (None, None),
    };
    let action = if is_connect {
        "connect".to_string()
    } else {
        action_for(method, path)
    };
    let user_agent = req_headers
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let context = serde_json::json!({
        "ip": client_addr.ip().to_string(),
        "user_agent": user_agent,
    });
    let body = DecideRequest {
        actor: None,
        host_token: token,
        host_token_kind: kind,
        action,
        target: path.to_string(),
        context,
        trace_id: state.next_trace_id(),
    };
    let url = format!("{}/v1/decide", state.config.daemon.trim_end_matches('/'));
    let mut rb = state.http.post(&url).json(&body);
    if let Some(t) = state.config.admin_token.as_deref() {
        rb = rb.header("X-Admin-Token", t);
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("daemon status {}", resp.status()));
    }
    let txt = resp
        .text()
        .await
        .map_err(|e| format!("daemon body read: {e}"))?;
    let decoded: DecideResponse =
        serde_json::from_str(&txt).map_err(|e| format!("daemon malformed body: {e}: {txt}"))?;
    if decoded.decision.is_empty() {
        return Err("daemon returned empty decision".to_string());
    }
    Ok(decoded)
}

/// Forward an HTTP request to the upstream service via reqwest and copy the
/// response back as a hyper response.
pub async fn forward_to_upstream(
    state: &ProxyState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, String> {
    let upstream_base = state.config.upstream.trim_end_matches('/').to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let url = format!("{upstream_base}{path_and_query}");

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| format!("bad method: {e}"))?;
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| format!("read req body: {e}"))?
        .to_bytes();

    let mut rb = state.http.request(method, &url);
    for (k, v) in parts.headers.iter() {
        // Skip hop-by-hop headers and host (reqwest sets it).
        let name = k.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) {
            continue;
        }
        rb = rb.header(k.as_str(), v.as_bytes());
    }
    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes.to_vec());
    }
    let upstream_resp = rb
        .send()
        .await
        .map_err(|e| format!("upstream error: {e}"))?;
    let status = upstream_resp.status();
    let mut builder = Response::builder().status(status.as_u16());
    for (k, v) in upstream_resp.headers().iter() {
        let name = k.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            builder = builder.header(hn, hv);
        }
    }
    let body = upstream_resp
        .bytes()
        .await
        .map_err(|e| format!("upstream body: {e}"))?;
    builder
        .body(Full::new(body))
        .map_err(|e| format!("response build: {e}"))
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("static response")
}

/// Top-level request handler. Returns a hyper response wrapping a buffered
/// body. Websocket upgrades are handled out of band by the connection driver
/// (see [`serve_connection`]).
pub async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let is_ws = is_websocket_upgrade(&req);

    // Span the entire decision lifetime under tf.daemon.decide so the
    // Grafana trace explorer can pivot on tf.action / tf.decision /
    // tf.actor_resolved exactly like the TS daemon does.
    let span = tracing::info_span!(
        "tf.daemon.decide",
        otel.name = "tf.daemon.decide",
        tf.action = %action_for(&method, &path),
        tf.target = %path,
        // Filled in once the decision lands. tracing supports
        // record-after-creation so we don't need to know these up front.
        tf.decision = tracing::field::Empty,
        tf.actor_resolved = tracing::field::Empty,
    );
    let _enter = span.enter();

    let started = std::time::Instant::now();
    let decision =
        match call_decide(&state, req.headers(), &method, &path, client_addr, is_ws).await {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "daemon decide failed");
                return Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"error": "daemon-error", "detail": e}),
                ));
            }
        };

    // Record the outcome on the active span and on the canonical metric
    // pipeline. Both are fire-and-forget; if telemetry is off they are
    // cheap no-ops.
    span.record("tf.decision", decision.decision.as_str());
    if let Some(otel) = state.otel() {
        let actor = "unknown";
        let action = action_for(&method, &path);
        let elapsed = started.elapsed().as_secs_f64();
        tf_otel::record_decide(
            otel.metrics(),
            &decision.decision,
            &action,
            actor,
            Some(&path),
            elapsed,
        );
    }

    info!(
        decision = %decision.decision,
        method = %method,
        path = %path,
        mode = ?state.config.mode,
        "decision"
    );

    match decision.decision.as_str() {
        "allow" => match forward_to_upstream(&state, req).await {
            Ok(r) => Ok(r),
            Err(e) => {
                error!(error = %e, "upstream forward failed");
                Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"error": "upstream-error", "detail": e}),
                ))
            }
        },
        "deny" => {
            if state.config.mode == Mode::Enforce {
                let realm = state
                    .config
                    .upstream
                    .parse::<Uri>()
                    .ok()
                    .and_then(|u| u.host().map(|s| s.to_string()))
                    .unwrap_or_else(|| state.config.profile.clone());
                let reason = decision.reason.clone().unwrap_or_default();
                let proof = decision.proof_id.clone().unwrap_or_default();
                let www_auth = format!("TrustForge realm=\"{realm}\", reason=\"{reason}\"");
                let body = serde_json::json!({
                    "error": "deny",
                    "reason": reason,
                    "proof_id": proof,
                });
                let mut resp = json_response(StatusCode::FORBIDDEN, body);
                if let Ok(hv) = HeaderValue::from_str(&www_auth) {
                    resp.headers_mut()
                        .insert(hyper::header::WWW_AUTHENTICATE, hv);
                }
                Ok(resp)
            } else {
                warn!(
                    proof_id = ?decision.proof_id,
                    reason = ?decision.reason,
                    "observe-only: forwarding despite deny"
                );
                match forward_to_upstream(&state, req).await {
                    Ok(r) => Ok(r),
                    Err(e) => Ok(json_response(
                        StatusCode::BAD_GATEWAY,
                        serde_json::json!({"error": "upstream-error", "detail": e}),
                    )),
                }
            }
        }
        "approval-required" | "approval_required" => {
            let approval_id = decision.approval_id.clone().unwrap_or_default();
            let location = format!(
                "{}/v1/approval/{}",
                state.config.daemon.trim_end_matches('/'),
                approval_id
            );
            let body = serde_json::json!({
                "status": "pending",
                "approval_id": approval_id,
            });
            let mut resp = json_response(StatusCode::ACCEPTED, body);
            if let Ok(hv) = HeaderValue::from_str(&location) {
                resp.headers_mut().insert(hyper::header::LOCATION, hv);
            }
            Ok(resp)
        }
        "log-only" | "log_only" => {
            info!(
                proof_id = ?decision.proof_id,
                reason = ?decision.reason,
                "proof-event log-only forwarding"
            );
            match forward_to_upstream(&state, req).await {
                Ok(r) => Ok(r),
                Err(e) => Ok(json_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"error": "upstream-error", "detail": e}),
                )),
            }
        }
        other => {
            warn!(decision = %other, "unknown decision; treating as deny");
            if state.config.mode == Mode::Enforce {
                Ok(json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({"error": "deny", "reason": format!("unknown decision: {other}")}),
                ))
            } else {
                match forward_to_upstream(&state, req).await {
                    Ok(r) => Ok(r),
                    Err(e) => Ok(json_response(
                        StatusCode::BAD_GATEWAY,
                        serde_json::json!({"error": "upstream-error", "detail": e}),
                    )),
                }
            }
        }
    }
}

/// Drive a single connection. If the request is a websocket upgrade (and the
/// daemon allows it), we transparently splice the client and upstream TCP
/// streams together. Otherwise we fall through to [`handle_request`].
pub async fn serve_connection(state: Arc<ProxyState>, stream: TcpStream, client_addr: SocketAddr) {
    // We need to peek at the request before deciding between websocket
    // splice and regular HTTP service. Use hyper with a service_fn that owns
    // a one-shot signal: when the handler sees a websocket upgrade we let
    // hyper finish the response (we'll send a 101 directly) and then take
    // the underlying TCP socket out of the connection.
    //
    // To keep the implementation simple and predictable, we read enough of
    // the first request to see the headers ourselves, decide, and then
    // either handle it inline as websocket or hand the original bytes to
    // hyper for normal processing.
    if let Err(e) = serve_connection_inner(state, stream, client_addr).await {
        debug!(error = %e, "connection ended");
    }
}

async fn serve_connection_inner(
    state: Arc<ProxyState>,
    mut stream: TcpStream,
    client_addr: SocketAddr,
) -> std::io::Result<()> {
    // Peek the first chunk to detect a websocket upgrade without consuming.
    let mut peek = [0u8; 4096];
    let n = stream.peek(&mut peek).await?;
    if n == 0 {
        return Ok(());
    }
    let head = &peek[..n];
    let is_ws = head_looks_like_websocket(head);

    if is_ws {
        // Parse method+path+headers minimally for the decide call.
        if let Some((method, path, headers)) = parse_request_head(head) {
            let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
            match call_decide(&state, &headers, &m, &path, client_addr, true).await {
                Ok(d) => {
                    let allow = d.decision == "allow"
                        || (state.config.mode == Mode::ObserveOnly
                            && d.decision != "approval-required"
                            && d.decision != "approval_required");
                    if allow {
                        info!(decision = %d.decision, "websocket upgrade allowed");
                        return splice_to_upstream(&state, stream).await;
                    } else if d.decision == "approval-required" || d.decision == "approval_required"
                    {
                        let approval_id = d.approval_id.unwrap_or_default();
                        let loc = format!(
                            "{}/v1/approval/{}",
                            state.config.daemon.trim_end_matches('/'),
                            approval_id
                        );
                        let body =
                            format!("{{\"status\":\"pending\",\"approval_id\":\"{approval_id}\"}}");
                        let resp = format!(
                            "HTTP/1.1 202 Accepted\r\nLocation: {loc}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        stream.write_all(resp.as_bytes()).await?;
                        return Ok(());
                    } else {
                        let reason = d.reason.unwrap_or_default();
                        let body = format!("{{\"error\":\"deny\",\"reason\":\"{reason}\"}}");
                        let resp = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        stream.write_all(resp.as_bytes()).await?;
                        return Ok(());
                    }
                }
                Err(e) => {
                    error!(error = %e, "ws decide failed");
                    let body = format!("{{\"error\":\"daemon-error\",\"detail\":\"{e}\"}}");
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(resp.as_bytes()).await?;
                    return Ok(());
                }
            }
        }
    }

    let io = TokioIo::new(stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { handle_request(state, req, client_addr).await }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await
    {
        debug!(error = %e, "hyper serve_connection error");
    }
    Ok(())
}

fn head_looks_like_websocket(buf: &[u8]) -> bool {
    let s = match std::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let head_end = match s.find("\r\n\r\n") {
        Some(i) => i,
        None => s.len(),
    };
    let head = &s[..head_end];
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("upgrade")
                && value.trim().eq_ignore_ascii_case("websocket")
            {
                return true;
            }
        }
    }
    false
}

fn parse_request_head(buf: &[u8]) -> Option<(String, String, hyper::HeaderMap)> {
    let s = std::str::from_utf8(buf).ok()?;
    let head_end = s.find("\r\n\r\n").unwrap_or(s.len());
    let head = &s[..head_end];
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = hyper::HeaderMap::new();
    for line in lines {
        if let Some((n, v)) = line.split_once(':') {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(n.trim().as_bytes()),
                HeaderValue::from_str(v.trim()),
            ) {
                headers.insert(hn, hv);
            }
        }
    }
    Some((method, path, headers))
}

async fn splice_to_upstream(state: &ProxyState, mut client: TcpStream) -> std::io::Result<()> {
    // Connect to upstream and pipe bytes both ways. We assume the upstream
    // URL is plain http://host:port (TLS upstream is out of scope for this
    // first cut; reverse-proxy TLS termination happens at the listener).
    let url = match state.config.upstream.parse::<Uri>() {
        Ok(u) => u,
        Err(e) => {
            error!(error = %e, "bad upstream URL");
            return Ok(());
        }
    };
    let host = url.host().unwrap_or("127.0.0.1");
    let port = url.port_u16().unwrap_or(match url.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    let mut upstream = TcpStream::connect((host, port)).await?;
    // Drain the peeked bytes from the client (we did not consume them
    // because we used `peek`) and ferry both directions.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Run the proxy until cancelled. Returns when the listener is dropped.
pub async fn run(state: Arc<ProxyState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(state.config.listen).await?;
    info!(listen = %state.config.listen, upstream = %state.config.upstream, "tf-proxy listening");
    let tls = build_tls_acceptor(&state.config)?;
    loop {
        let (stream, addr) = listener.accept().await?;
        let s = state.clone();
        match &tls {
            Some(acceptor) => {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = serve_tls(s, acceptor, stream, addr).await;
                });
            }
            None => {
                tokio::spawn(async move {
                    serve_connection(s, stream, addr).await;
                });
            }
        }
    }
}

fn build_tls_acceptor(cfg: &ProxyConfig) -> std::io::Result<Option<TlsAcceptor>> {
    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_file = std::fs::File::open(cert_path)?;
            let key_file = std::fs::File::open(key_path)?;
            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut BufReader::new(cert_file))
                    .collect::<Result<Vec<_>, _>>()?;
            let key =
                rustls_pemfile::private_key(&mut BufReader::new(key_file))?.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "no private key in pem file",
                    )
                })?;
            let cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(Some(TlsAcceptor::from(Arc::new(cfg))))
        }
        (None, None) => Ok(None),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--tls-cert and --tls-key must be provided together",
        )),
    }
}

async fn serve_tls(
    state: Arc<ProxyState>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let tls_stream = acceptor.accept(stream).await?;
    let io = TokioIo::new(tls_stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { handle_request(state, req, addr).await }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await
    {
        debug!(error = %e, "tls hyper error");
    }
    Ok(())
}
