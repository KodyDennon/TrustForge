# TF-0013: Site-to-Site Binary Path

- **Status**: Draft
- **Layer**: 9 (Network / Transport)
- **Created**: 2026-04-25

## 1. Abstract

This specification defines the "Binary Path" for TrustForge site-to-site communication. It allows two TrustForge-enabled sites to establish a secure, identity-asserted tunnel over raw TCP or TLS, carrying bidirectional HTTP traffic via a specialized ProofRPC method kind (`http-bridge`).

## 2. Transport Layer Framing

When driving a TrustForge session over a streaming transport (like TCP) rather than a message-oriented transport (like WebSocket), implementations MUST use a length-delimited framing layer.

### 2.1. Frame Format

Each frame consists of a 4-byte header followed by the session payload:

- **Length** (4 bytes): Big-endian unsigned 32-bit integer representing the length of the payload in bytes.
- **Payload** (N bytes): The canonical-JSON handshake frame or the AEAD-encrypted data frame.

```text
+----------------------------+--------------------------------+
| Length (32-bit BE, 4 bytes)| Payload (N bytes)              |
+----------------------------+--------------------------------+
```

Implementations SHOULD enforce a maximum frame size (default 1MB) to prevent memory exhaustion attacks.

## 3. ProofRPC `http-bridge` Kind

The `http-bridge` method kind is a specialized bidirectional stream designed to carry HTTP/1.1 or HTTP/2 semantics.

### 3.1. Method Declaration

In a ProofRPC service descriptor, a site-to-site bridge is declared with `kind: http-bridge`.

```json
{
  "name": "http.proxy",
  "kind": "http-bridge",
  "capability": "http.proxy",
  "description": "Cross-site HTTP tunnel"
}
```

### 3.2. Data Frames (`HttpFrame`)

The `http-bridge` stream carries an asynchronous sequence of `HttpFrame` objects in both directions.

#### RequestHeaders
Sent by the initiator to start a request.
- `method`: HTTP verb (e.g., "GET", "POST").
- `path`: Request URI (e.g., "/api/v1/resource").
- `headers`: Map of string keys to string values.

#### ResponseHeaders
Sent by the responder after receiving `RequestHeaders`.
- `status`: HTTP status code (e.g., 200).
- `headers`: Map of string keys to string values.

#### BodyChunk
Sent by either side to carry request/response bodies.
- `data`: Base64-encoded binary chunk.

#### Trailers
Sent at the end of a body stream.
- `headers`: Map of optional HTTP trailers.

## 4. Lifecycle & State Machine

1. **Handshake**: Peers establish a standard TrustForge session (TF-0002).
2. **Call**: The initiator issues an `rpc-call` with `method_kind: http-bridge`.
3. **Pumping**:
    - Initiator MUST send `request-headers` as the first frame.
    - Initiator sends zero or more `body-chunk` frames.
    - Responder sends `response-headers` once the upstream request is initiated.
    - Responder sends zero or more `body-chunk` frames.
4. **Termination**: Either side sends a frame with `more: false` to signal end-of-stream.

## 5. Implementation Requirements

### 5.1. Streaming
Implementations MUST support streaming bodies. They SHOULD NOT buffer the entire HTTP body before yielding chunks to the TrustForge session.

### 5.2. Flow Control
Implementations MUST respect the underlying transport's backpressure. If the TrustForge session is congested, the implementation SHOULD pause reading from the local HTTP socket.

### 5.3. Capability Enforcement
Sites MUST NOT allow the `http-bridge` method to be called by default. Access MUST be granted via an explicit policy rule or `permission-grant`.

```yaml
# Example policy rule
- target: "tf:actor:agent:remote-site.com/*"
  allow: ["http.proxy"]
  constraints:
    target_glob: "http://internal-service:8080/*"
```

## 6. Security Considerations

- **Identity-Based Routing**: The tunnel is tied to the cryptographic identity of the calling site. The responder SHOULD log all proxied traffic against the caller's thumbprint.
- **End-to-End Encryption**: The HTTP traffic is wrapped in the session's ChaCha20-Poly1305 AEAD. Even if carried over raw TCP, the traffic is secure against eavesdropping.
- **SSRF Prevention**: Implementations SHOULD validate the `target_url` hint in the `rpc-call` request against an allowlist of internal services.
