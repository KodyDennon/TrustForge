# tf-linkerd-controller

A Linkerd policy integration that delegates per-Server authorization to a
TrustForge daemon (`tf-daemon`).

**Status:** Draft — Phase 0. Experimental, not production-ready. This
controller is exercised against the working reference daemon, but remains
mock-tested until a cluster smoke test is added.

## How it works

Linkerd expresses request authorization with two CRDs:

- `policy.linkerd.io/v1beta1.Server` — selects pod/port pairs.
- `policy.linkerd.io/v1beta1.ServerAuthorization` — allow rules
  (`client.meshTLS.identities[]` / `client.unauthenticated`).

The controller watches every `Server` cluster-wide and synthesises a
companion `ServerAuthorization` named `<server>-trustforge`. For each
Server it issues:

```http
POST /v1/decide
Content-Type: application/json

{"actor":"linkerd-controller","action":"linkerd.authz.server","target":"<ns>/<server>"}
```

`tf-daemon` answers with a `decision` and an optional list of allowed
mesh-TLS `identities`. The controller writes those identities into the
ServerAuthorization. On any error or `decision != "allow"` the
identities list is emptied (fail-closed: nobody can talk to the
Server).

## Build

This integration is written in Go (1.22+). Install Go from
<https://go.dev/dl/> if it is not already on the host.

```sh
cd tools/native/linkerd
go build ./cmd/tf-linkerd-controller
```

## Test

```sh
go test ./...
```

The test suite spins up an `httptest.Server` standing in for `tf-daemon`
and a fake dynamic Kubernetes client; it covers the happy `allow` path
and the fail-closed daemon-error path.

## Deploy

The example manifest in `manifests/policy-controller.yaml` creates a
namespace, a ServiceAccount, the cluster RBAC the controller needs, and
the controller Deployment. It also includes a sample `Server` and a
seed `ServerAuthorization` that starts in fail-closed state.

```sh
kubectl apply -f manifests/policy-controller.yaml
```

## Files

- `go.mod` — module manifest.
- `cmd/tf-linkerd-controller/main.go` — controller entry-point.
- `cmd/tf-linkerd-controller/main_test.go` — happy/sad path tests.
- `manifests/policy-controller.yaml` — RBAC + Deployment + sample
  Server/ServerAuthorization.

## Dependencies

- Go 1.22+.
- A Kubernetes cluster with Linkerd installed (`linkerd install` from
  Linkerd 2.13+).
