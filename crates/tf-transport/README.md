# tf-transport

First-party transport primitives for TrustForge.

The current production slice provides a small async HTTP/1.1 client for
plain `http://` local-service calls. It is used by `tf-decide-client`
and `tf-prom-exporter` so TrustForge-owned local daemon traffic no
longer depends on `reqwest`.

Scope today:

- `GET` and `POST`.
- One request per TCP connection.
- `Connection: close`.
- `Content-Length`, chunked, and close-framed responses.
- Optional bearer auth and custom headers.
- Explicit timeout and response-size cap.
- Strict request-header validation: callers cannot inject or override
  `Host`, `Connection`, `Content-Length`, or `Transfer-Encoding`.
- Strict response-framing validation: conflicting `Content-Length`,
  mixed `Transfer-Encoding`/`Content-Length`, malformed chunk framing,
  and ambiguous authorities are rejected.
- IPv6 bracket authorities and query-only request targets are handled
  without depending on a URL parser crate.

Intentional limit: HTTPS, TLS 1.3, QUIC, and HTTP/3 are not claimed by
this first slice. Those land behind explicit experimental features after
the transport conformance and audit gates described in
`docs/dependency-replacement-roadmap.md`.
