# tf-envoy-filter

A `proxy-wasm` HTTP filter for [Envoy](https://www.envoyproxy.io/) that
asks a TrustForge daemon (`tf-daemon`) whether each request should be
allowed.

**Status:** Draft — Phase 0. Experimental, not production-ready. This
filter is exercised against the working reference daemon, but remains
mock-tested.

## How it works

`HttpContext::on_http_request_headers` is invoked for every inbound
request. The filter:

1. Reads `:authority`, `:method`, `:path`, `Authorization`, `Cookie`.
2. Dispatches an HTTP callout to a configured `tf_daemon` cluster:

   ```http
   POST /v1/decide
   Content-Type: application/json

   {"actor":"<authz-or-cookie>","action":"http.<verb>.<top-segment>","target":"<authority><path>"}
   ```

3. On `decision: "allow"` the request is resumed; on `deny` (or any
   non-allow / parse-failure / callout-error) the filter replies **403**
   with the daemon's reason. Callout failure replies **503**.

Envoy wasm filters cannot make arbitrary outbound HTTP calls; they can
only target clusters that exist in the static config. The example
`envoy.yaml.example` declares a `tf_daemon` cluster pointing at
`127.0.0.1:8765`.

## Build

```sh
# Install the target the first time.
rustup target add wasm32-wasi

# Build the wasm cdylib.
cargo build --target wasm32-wasi --release

# Output:
ls target/wasm32-wasi/release/tf_envoy_filter.wasm
```

> If your toolchain ships only `wasm32-unknown-unknown` (some platforms),
> use `--target wasm32-unknown-unknown` and add `crate-type = ["cdylib"]`
> as already declared. Envoy 1.27+ accepts both.

Copy the artefact:

```sh
sudo cp target/wasm32-wasi/release/tf_envoy_filter.wasm \
        /etc/envoy/tf-envoy-filter.wasm
sudo systemctl restart envoy   # or whatever runs your Envoy
```

## Test

```sh
cargo test                # host-side tests
cargo build --target wasm32-wasi --release   # wasm build sanity
```

Host-side `cargo test` exercises the deterministic helpers
(`build_decide_request`, `to_json`, `parse_decide_response`). The
proxy-wasm runtime shim cannot be driven from a host process without a
real wasm runtime; `proxy-wasm-test = "0.2"` does not exist on crates.io
as of writing, so we hand-roll a host-side mock in
`tests/filter_logic.rs`.

## Configure

The example `envoy.yaml.example` shows the minimal listener config. Key
points:

- The wasm filter must come **before** `envoy.filters.http.router`.
- A `tf_daemon` cluster (or whatever name you pass via filter
  configuration) must exist; otherwise `dispatch_http_call` fails and
  the filter replies 503.
- Set `vm_config.runtime` to `envoy.wasm.runtime.v8` (V8) for production
  or `envoy.wasm.runtime.wasmtime` for the experimental Wasmtime runtime.

## Files

- `Cargo.toml` — crate manifest. `proxy-wasm` is a wasm-target-only
  dependency to keep host-side `cargo test` green.
- `src/lib.rs` — pure helpers + `proxy-wasm` `HttpContext` impl.
- `envoy.yaml.example` — minimal listener wiring.
- `tests/filter_logic.rs` — host-side unit tests.

## Dependencies

- Rust toolchain (1.75+).
- `wasm32-wasi` (or `wasm32-unknown-unknown`) target.
- An Envoy build with `envoy.filters.http.wasm` enabled (default in
  upstream Envoy).
