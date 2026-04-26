# 03 — Rust server with Axum

Goal: wire the `tf-axum` adapter (under `crates/adapters/`) into
an Axum HTTP server so that one route is gated by a TrustForge
policy decision. About 25 minutes.

This is the Rust counterpart to
[02 Protect an app](02-protect-an-app.md). The two are equivalent
in behaviour — same surfaces, same proof events — but you may
prefer the Rust path for performance, type safety, or ecosystem
reasons.

By the end you will have:

- An Axum server protecting a route with `tf-axum` middleware.
- The same policy decisions and proof events you saw in tutorial
  02, just emitted by Rust code.

## Prerequisites

- Tutorial 01 completed and a daemon running on
  `127.0.0.1:8787`.
- Rust ≥ 1.78.

## Step 1 — Create a new crate

```bash
mkdir -p ~/tf-tutorial-03 && cd ~/tf-tutorial-03
cargo init --bin
```

Edit `Cargo.toml`:

```toml
[package]
name = "tf-tutorial-03"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Path dependency to your local TrustForge checkout.
tf-axum = { path = "/path/to/trustforge/crates/adapters/tf-axum" }
tf-types = { path = "/path/to/trustforge/crates/tf-types" }
```

Adjust the paths to wherever you cloned TrustForge.

## Step 2 — A tiny Axum server

Replace `src/main.rs`:

```rust
use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use tf_axum::{TrustForgeLayer, decide};
use tf_types::actor::ActorUri;

#[derive(Clone)]
struct App {
    tf: Arc<tf_axum::Client>,
}

#[tokio::main]
async fn main() {
    let admin_token = std::env::var("TF_ADMIN_TOKEN").expect("TF_ADMIN_TOKEN");
    let tf = Arc::new(
        tf_axum::Client::builder()
            .daemon("http://127.0.0.1:8787")
            .admin_token(admin_token)
            .adapter(ActorUri::parse("tf:actor:service:example.com/tutorial-03-adapter").unwrap())
            .build()
            .expect("client"),
    );

    let state = App { tf: tf.clone() };

    let app = Router::new()
        .route("/public", get(public_route))
        .route(
            "/protected/:doc",
            get(protected_route).layer(TrustForgeLayer::new(tf.clone(), |req, params: &Path<String>| {
                decide("doc.read")
                    .target(format!("doc:{}", params.0))
                    .actor_from_header(&req.headers, "x-actor")
            })),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await.unwrap();
    println!("listening on :3001");
    axum::serve(listener, app).await.unwrap();
}

async fn public_route() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "route": "public" }))
}

async fn protected_route(Path(doc): Path<String>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "route": "protected", "doc": doc }))
}
```

The `TrustForgeLayer` middleware:

1. Builds a `decide` request from the URL params and headers.
2. Calls the daemon's `/v1/decide` endpoint with the adapter's
   admin token.
3. On `allow`, calls the inner handler.
4. On `deny` or unmet `escalate`, returns 403 with the daemon's
   reasons.

## Step 3 — Same policy as tutorial 02

Re-use the policy from tutorial 02:

```yaml
# .tf/policy.yaml in your TrustForge checkout
engine: cedar
schema: |
  entity Action;
  entity Actor;
  entity Target;
rules: |
  permit (
    principal == Actor::"tf:actor:human:example.com/alice",
    action == Action::"doc.read",
    resource
  );

  forbid (
    principal,
    action == Action::"doc.read",
    resource == Target::"doc:executive-comp"
  );
```

Reload via `/v1/policy/reload` or `SIGHUP` as before.

## Step 4 — Boot the Rust server

```bash
cd ~/tf-tutorial-03
TF_ADMIN_TOKEN=… cargo run
# listening on :3001
```

## Step 5 — Smoke test

```bash
curl -s http://127.0.0.1:3001/public | jq .
# { "ok": true, "route": "public" }

curl -s http://127.0.0.1:3001/protected/sales-report \
    -H "X-Actor: tf:actor:human:example.com/alice" | jq .
# { "ok": true, "route": "protected", "doc": "sales-report" }

curl -s -i http://127.0.0.1:3001/protected/executive-comp \
    -H "X-Actor: tf:actor:human:example.com/alice"
# HTTP/1.1 403 Forbidden
# {"ok":false,"reason":"forbid rule matched","decision":"deny"}
```

Behaviour matches tutorial 02. The proof events emitted by the
daemon are identical — the Rust side does not produce a different
ledger format.

## Step 6 — Streaming and proof events on the Rust side

The Rust adapter exposes the proof event id of each decision via
a response extension:

```rust
async fn protected_route(
    Path(doc): Path<String>,
    tf_axum::ProofEventId(pe_id): tf_axum::ProofEventId,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "route": "protected",
        "doc": doc,
        "proof_event_id": pe_id
    }))
}
```

This is useful when the response itself needs to be auditable:
include `proof_event_id` in your application logs, and a
downstream auditor can pull the matching event from the daemon.

## Step 7 — In-process ProofRPC

For higher-performance internal calls, skip HTTP and use the
ProofRPC stream directly. The Rust side ships the wire format
in `tf-types::rpc`:

```rust
// Pseudocode — see crates/tf-code-helper-example/ for a working
// reference.
let stream = tf_axum::rpc(tf.clone())
    .open("doc.share", "doc:exec-comp", actor_uri)
    .await?;
stream.send(/* command */).await?;
let response = stream.recv().await?;
```

The example crate `tf-code-helper-example` (under
`crates/tf-code-helper-example/`) is a downstream consumer that
compiles ProofRPC-generated code from the
`examples/proofrpc/code-helper.tfrpc.yaml` service descriptor.
Use it as a template for your own services.

## Step 8 — Embedding into a larger app

Production tips:

- Build the `tf_axum::Client` once at startup; share it via
  `Arc<Client>`.
- Pin the adapter actor URI; do not mint it dynamically.
- Use `tower::limit::ConcurrencyLimitLayer` upstream of the TF
  layer to keep the daemon's `/v1/decide` rate bounded.
- Log the `request_id` from the response so you can correlate
  app logs to daemon logs.
- For health probes, exclude the TF layer from the `/health` and
  `/metrics` routes.

## What you have learned

- Rust apps wire to TrustForge through the same surfaces as TS
  apps.
- The decision boundary is the daemon, not the adapter; the
  adapter is a thin tower-layer.
- Per-decision proof events are available to the application as
  response metadata.

## What to read next

- [04 Policy authoring](04-policy-authoring.md) — write Cedar and
  Rego policies that scale beyond toy examples.
- [05 Federation](05-federation.md) — connect your Rust server's
  domain to a partner domain.
- [`../architecture/data-flows.md`](../architecture/data-flows.md)
  — see flow C, the `/v1/decide` data flow you just wired.

## Adapter source

The `tf-axum` crate lives in
[`../../crates/adapters/`](../../crates/adapters/). Other Rust
adapters under that directory cover Tonic, Tower, and a generic
hyper service-fn. The tower middleware shape is the same; the
extractors differ per framework.
