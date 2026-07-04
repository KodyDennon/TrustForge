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
    MalformedDetail(String),
    TimedOut,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::UnsupportedUrl(u) => write!(f, "unsupported URL (http:// only): {u}"),
            HttpError::InvalidHeader(h) => write!(f, "invalid HTTP header: {h}"),
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::Malformed(what) => write!(f, "malformed HTTP response: {what}"),
            HttpError::MalformedDetail(what) => write!(f, "malformed HTTP response: {what}"),
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
        if response_complete(&raw)? {
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
        if is_reserved_request_header(name) {
            return Err(HttpError::InvalidHeader(name.clone()));
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(HttpError::InvalidHeader(name.clone()));
        }
    }
    Ok(())
}

fn is_reserved_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "connection" | "content-length" | "transfer-encoding"
    )
}

/// Split `http://host[:port]/path` into (address, host header, path).
fn parse_url(url: &str) -> Result<(String, String, String), HttpError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| HttpError::UnsupportedUrl(url.to_string()))?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('#')
        || authority.bytes().any(|b| b <= 0x20 || b == b'/')
    {
        return Err(HttpError::UnsupportedUrl(url.to_string()));
    }

    let (addr, host_header) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let end = after_bracket
            .find(']')
            .ok_or_else(|| HttpError::UnsupportedUrl(url.to_string()))?;
        let host = &after_bracket[..end];
        let rest = &after_bracket[end + 1..];
        if host.is_empty() {
            return Err(HttpError::UnsupportedUrl(url.to_string()));
        }
        let port = if rest.is_empty() {
            "80"
        } else {
            rest.strip_prefix(':')
                .filter(|p| valid_port(p))
                .ok_or_else(|| HttpError::UnsupportedUrl(url.to_string()))?
        };
        (format!("[{host}]:{port}"), authority.to_string())
    } else if authority.matches(':').count() > 1 {
        return Err(HttpError::UnsupportedUrl(url.to_string()));
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() || !valid_port(port) {
            return Err(HttpError::UnsupportedUrl(url.to_string()));
        }
        (authority.to_string(), authority.to_string())
    } else {
        (format!("{authority}:80"), authority.to_string())
    };
    Ok((addr, host_header, path))
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn response_complete(raw: &[u8]) -> Result<bool, HttpError> {
    let Some(header_end) = find_header_end(raw) else {
        return Ok(false);
    };
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let framing = response_framing(&head)?;
    if let Some(len) = framing.content_length {
        return Ok(raw.len() >= header_end + len);
    }
    if framing.chunked {
        return Ok(decode_chunked(&raw[header_end..]).is_ok());
    }
    Ok(false)
}

#[derive(Debug, Default)]
struct ResponseFraming {
    content_length: Option<usize>,
    chunked: bool,
}

fn response_framing(head: &str) -> Result<ResponseFraming, HttpError> {
    let mut framing = ResponseFraming::default();
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::MalformedDetail(format!(
                "header line without colon: {line}"
            )));
        };
        if name.bytes().any(|b| b <= 0x20) {
            return Err(HttpError::MalformedDetail(format!(
                "invalid header name: {name}"
            )));
        }
        if value.starts_with(' ') && value.trim_start().starts_with([' ', '\t']) {
            return Err(HttpError::Malformed("obsolete folded header"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| HttpError::Malformed("bad content-length"))?;
            match framing.content_length {
                Some(existing) if existing != parsed => {
                    return Err(HttpError::Malformed("conflicting content-length"));
                }
                Some(_) => {}
                None => framing.content_length = Some(parsed),
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            let codings = value
                .split(',')
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>();
            if codings.last().is_some_and(|v| v == "chunked") {
                framing.chunked = true;
            } else if codings.iter().any(|v| v == "chunked") {
                return Err(HttpError::Malformed("chunked transfer-coding is not final"));
            }
        }
    }
    if framing.chunked && framing.content_length.is_some() {
        return Err(HttpError::Malformed(
            "both transfer-encoding and content-length present",
        ));
    }
    Ok(framing)
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(HttpError::Malformed("incomplete chunk header"))?;
        let size_text = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| HttpError::Malformed("chunk header is not utf-8"))?;
        let size_part = size_text
            .trim()
            .split(';')
            .next()
            .ok_or(HttpError::Malformed("empty chunk size"))?;
        let size = usize::from_str_radix(size_part, 16)
            .map_err(|_| HttpError::Malformed("bad chunk size"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            if rest.windows(2).position(|w| w == b"\r\n").is_none() {
                return Err(HttpError::Malformed("incomplete chunk trailers"));
            }
            return Ok(out);
        }
        if rest.len() < size + 2 || &rest[size..size + 2] != b"\r\n" {
            return Err(HttpError::Malformed("incomplete chunk body"));
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
    let framing = response_framing(&head)?;
    let headers = parse_headers(&head)?;
    let body_raw = &raw[header_end..];
    let body = if let Some(len) = framing.content_length {
        if body_raw.len() < len {
            return Err(HttpError::Malformed("body shorter than content-length"));
        }
        body_raw[..len].to_vec()
    } else if framing.chunked {
        decode_chunked(body_raw)?
    } else {
        body_raw.to_vec()
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn parse_headers(head: &str) -> Result<Vec<(String, String)>, HttpError> {
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::Malformed("header line without colon"));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(headers)
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
    fn parses_query_only_and_ipv6_urls() {
        assert_eq!(
            parse_url("http://example.com?x=1").unwrap(),
            (
                "example.com:80".to_string(),
                "example.com".to_string(),
                "/?x=1".to_string()
            )
        );
        assert_eq!(
            parse_url("http://[::1]:8080/v1").unwrap(),
            (
                "[::1]:8080".to_string(),
                "[::1]:8080".to_string(),
                "/v1".to_string()
            )
        );
    }

    #[test]
    fn rejects_ambiguous_authorities() {
        for url in [
            "http://user@example.com/",
            "http://example.com:abc/",
            "http://::1/",
            "http://exa mple.com/",
        ] {
            assert!(
                matches!(parse_url(url), Err(HttpError::UnsupportedUrl(_))),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_header_injection() {
        let err = validate_headers(&[("X-Test".into(), "ok\r\nbad".into())]).unwrap_err();
        assert!(matches!(err, HttpError::InvalidHeader(_)));
    }

    #[test]
    fn rejects_reserved_request_headers() {
        let err = validate_headers(&[("Content-Length".into(), "1".into())]).unwrap_err();
        assert!(matches!(err, HttpError::InvalidHeader(_)));
    }

    #[test]
    fn status_errors_surface() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\ndeny";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body, b"deny");
    }

    #[test]
    fn rejects_conflicting_response_framing() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab";
        assert!(matches!(
            parse_response(raw),
            Err(HttpError::Malformed("conflicting content-length"))
        ));

        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(matches!(
            parse_response(raw),
            Err(HttpError::Malformed(
                "both transfer-encoding and content-length present"
            ))
        ));
    }
}
