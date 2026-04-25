# TrustForge Transport Binding

> `$id`: `https://trustforge.io/schemas/v0/transport-binding.schema.json`

Describes the underlying transport a TrustForge session is currently bound to. Used for session migration (TF-0003) and for relay path policy decisions.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `binding_version` | `"1"` | ✓ | Version of the transport-binding schema itself. |
| `kind` | `"websocket"` \| `"quic"` \| `"tcp"` \| `"ipc"` \| `"ble"` \| `"serial"` \| `"lora"` \| `"matrix"` \| `"grpc"` \| `"memory"` | ✓ | Underlying transport family. |
| `endpoint` | string | · | Transport-specific endpoint (URL, COM port, BLE peripheral name, ...). |
| `exporter_key` | string | · | Optional base64 of the TLS / QUIC exporter-keying-material output that binds this session to the underlying transport handshake. |
| `peer_cert_fingerprint` | string | · | Optional SHA-256 fingerprint of the peer's TLS certificate, in hex. |
| `tls_alpn` | string | · | Negotiated ALPN identifier when the transport is TLS-bearing. |
| `established_at` | [`Timestamp`](./_common.md#timestamp) | · |  |
| `metadata` | object | · | Free-form transport-specific metadata. |
