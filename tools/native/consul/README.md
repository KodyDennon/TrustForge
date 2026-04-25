# tf-consul-intentions-backend

A small HTTP service that fronts Consul Connect's intention-check
endpoint and delegates each verdict to the local TrustForge daemon
(`tf-daemon`).

**Status:** Draft — Phase 0. Experimental, not production-ready. The
reference `tf-daemon` is not yet shipped.

## How it works

Consul Connect's intention API is the way operators express "service
A may dial service B". This binary exposes the same shape:

```http
POST /v1/intention/check
Content-Type: application/json

{ "Source": "web", "Destination": "db" }
```

(also reachable via `/v1/connect/intentions/check` and via
`GET …?source=web&destination=db`) and translates each request into:

```http
POST <tf-daemon>/v1/decide
Content-Type: application/json

{ "actor": "web", "action": "consul.connect.dial", "target": "db" }
```

`decision: "allow"` returns `{"Allowed": true}`; anything else, or any
daemon error, returns `{"Allowed": false}` (fail-closed) with the
daemon's `reason` echoed back.

## Build

This integration is written in Go (1.22+). Install Go from
<https://go.dev/dl/> if it is not already on the host.

```sh
cd tools/native/consul
go build ./intentions-backend
```

## Test

```sh
go test ./...
```

## Deploy

1. Run `tf-daemon` on the same host (defaults to `:8765`).
2. Run this binary: `./intentions-backend --addr :9000`.
3. Drop `consul-config.json` into `/etc/consul.d/` and reload Consul so
   the agent registers the service.
4. Configure your Connect-enabled sidecars to consult
   `http://127.0.0.1:9000/v1/intention/check` before allowing inbound
   traffic.

## Files

- `go.mod` — module manifest.
- `intentions-backend/main.go` — HTTP server.
- `intentions-backend/main_test.go` — happy/sad/query-string tests.
- `consul-config.json` — sample Consul agent config snippet.

## Dependencies

- Go 1.22+.
- A Consul agent (1.16+) with Connect enabled.
