//! First-party transport primitives for TrustForge-owned clients.
//!
//! This crate currently owns the plain HTTP/1.1 client used for local
//! daemon calls. HTTPS/TLS/QUIC/HTTP3 are intentionally not hidden here
//! yet; they will land as named, audit-gated transport backends.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    timeout: Duration,
    max_response_bytes: usize,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum HttpError {
    UnsupportedUrl(String),
    InvalidHeader(String),
    Io(std::io::Error),
    Malformed(&'static str),
    TimedOut,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::UnsupportedUrl(u) => write!(f, "unsupported URL (http:// only): {u}"),
            HttpError::InvalidHeader(h) => write!(f, "invalid HTTP header: {h}"),
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::Malformed(what) => write!(f, "malformed HTTP response: {what}"),
            HttpError::TimedOut => write!(f, "request timed out"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

impl HttpRequest {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: Duration::from_secs(5),
            max_response_bytes: 16 * 1024 * 1024,
        }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url)
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self::new(Method::Post, url)
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn bearer_auth(self, token: impl AsRef<str>) -> Self {
        let token = token.as_ref();
        if token.is_empty() {
            self
        } else {
            self.header("Authorization", format!("Bearer {token}"))
        }
    }

    pub fn json_body(self, bytes: Vec<u8>) -> Self {
        self.header("Content-Type", "application/json").body(bytes)
    }

    pub fn body(mut self, bytes: Vec<u8>) -> Self {
        self.body = bytes;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    pub async fn send(self) -> Result<HttpResponse, HttpError> {
        tokio::time::timeout(self.timeout, send_inner(self))
            .await
            .map_err(|_| HttpError::TimedOut)?
    }
}

pub async fn get_text(url: &str, timeout: Duration) -> Result<String, HttpError> {
    let resp = HttpRequest::get(url).timeout(timeout).send().await?;
    String::from_utf8(resp.body).map_err(|_| HttpError::Malformed("response body is not utf-8"))
}

async fn send_inner(req: HttpRequest) -> Result<HttpResponse, HttpError> {
    validate_headers(&req.headers)?;
    let (addr, host, path) = parse_url(&req.url)?;
    let mut stream = TcpStream::connect(&addr).await?;

    let mut raw_request = format!(
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        req.method.as_str()
    );
    for (name, value) in &req.headers {
        raw_request.push_str(name);
        raw_request.push_str(": ");
        raw_request.push_str(value);
        raw_request.push_str("\r\n");
    }
    if !req.body.is_empty() || req.method == Method::Post {
        raw_request.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    raw_request.push_str("\r\n");
    stream.write_all(raw_request.as_bytes()).await?;
    if !req.body.is_empty() {
        stream.write_all(&req.body).await?;
    }

    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > req.max_response_bytes {
            return Err(HttpError::Malformed("response exceeds configured cap"));
        }
        if response_complete(&raw).unwrap_or(false) {
            break;
        }
    }
    parse_response(&raw)
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), HttpError> {
    for (name, value) in headers {
        if name.is_empty()
            || name
                .bytes()
                .any(|b| b <= 0x20 || b == b':' || b == b'\r' || b == b'\n')
        {
            return Err(HttpError::InvalidHeader(name.clone()));
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(HttpError::InvalidHeader(name.clone()));
        }
    }
    Ok(())
}

/// Split `http://host[:port]/path` into (address, host header, path).
fn parse_url(url: &str) -> Result<(String, String, String), HttpError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| HttpError::UnsupportedUrl(url.to_string()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(HttpError::UnsupportedUrl(url.to_string()));
    }
    let with_port = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    Ok((with_port, authority.to_string(), path.to_string()))
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn response_complete(raw: &[u8]) -> Option<bool> {
    let header_end = find_header_end(raw)?;
    let head = String::from_utf8_lossy(&raw[..header_end]);
    if let Some(len) = content_length(&head) {
        return Some(raw.len() >= header_end + len);
    }
    if is_chunked(&head) {
        return Some(decode_chunked(&raw[header_end..]).is_some());
    }
    Some(false)
}

fn content_length(head: &str) -> Option<usize> {
    for line in head.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

fn is_chunked(head: &str) -> bool {
    for line in head.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                return true;
            }
        }
    }
    false
}

fn decode_chunked(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.trim().split(';').next()?, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if rest.len() < size + 2 || &rest[size..size + 2] != b"\r\n" {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, HttpError> {
    let header_end = find_header_end(raw).ok_or(HttpError::Malformed("no header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let status_line = head.lines().next().ok_or(HttpError::Malformed("empty"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or(HttpError::Malformed("status line"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Malformed("not HTTP/1.x"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::Malformed("status code"))?;
    let headers = parse_headers(&head);
    let body_raw = &raw[header_end..];
    let body = if let Some(len) = content_length(&head) {
        if body_raw.len() < len {
            return Err(HttpError::Malformed("body shorter than content-length"));
        }
        body_raw[..len].to_vec()
    } else if is_chunked(&head) {
        decode_chunked(body_raw).ok_or(HttpError::Malformed("incomplete chunked body"))?
    } else {
        body_raw.to_vec()
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn parse_headers(head: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{}");
        assert_eq!(
            r.headers,
            vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "2".to_string())
            ]
        );
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n2\r\n\":\r\n2\r\n1}\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body, b"{\"a\":1}".to_vec());
    }

    #[test]
    fn rejects_https() {
        assert!(matches!(
            parse_url("https://example.com/x"),
            Err(HttpError::UnsupportedUrl(_))
        ));
    }

    #[test]
    fn rejects_header_injection() {
        let err = validate_headers(&[("X-Test".into(), "ok\r\nbad".into())]).unwrap_err();
        assert!(matches!(err, HttpError::InvalidHeader(_)));
    }

    #[test]
    fn status_errors_surface() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\ndeny";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body, b"deny");
    }
}
