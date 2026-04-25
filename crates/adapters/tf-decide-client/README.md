# tf-decide-client

Tiny shared HTTP client used by every `tf-*` framework adapter (axum, tonic,
actix-web, rocket, warp, poem, salvo, hyper) to call `tf-daemon`'s
`/v1/decide` endpoint.

## Why it exists

Without a shared crate, every adapter would re-define `DecideRequest` /
`DecideResponse` and re-implement bearer-token auth + JSON encode + error
classification. By extracting one client we keep the adapters small and
guarantee they all agree on the wire format.

## Usage

```rust
use tf_decide_client::{TfDecideClient, DecideRequest};

#[tokio::main]
async fn main() {
    let client = TfDecideClient::new("http://127.0.0.1:7080", "admin-token");
    let resp = client
        .decide(&DecideRequest {
            action: "GET /api/widgets".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    println!("decision={} reason={}", resp.decision, resp.reason);
}
```

## Status

Draft / experimental — wire format follows `TF-0007` decide-API draft and may
shift before 1.0.
