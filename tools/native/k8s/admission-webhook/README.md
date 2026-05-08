# tf-admission-webhook

A Kubernetes `ValidatingAdmissionWebhook` that consults a local TrustForge
daemon (`tf-daemon`) for an authorization decision before allowing API server
operations.

**Status:** Draft — Phase 0. Experimental, not production-ready. This
webhook is exercised against the working reference daemon, but remains
mock-tested until a cluster smoke test is added.

## What it does

For every `AdmissionReview` the webhook receives, it calls

```http
POST {tf-daemon}/v1/decide
Content-Type: application/json

{
  "actor":  "system:serviceaccount:<ns>:<sa>",
  "action": "k8s.<verb>.<resource>",
  "target": "<namespace>/<name>"
}
```

| daemon response          | webhook returns                          |
|--------------------------|------------------------------------------|
| `{"decision":"allow"}`   | `AdmissionResponse{Allowed: true}`       |
| `{"decision":"deny"...}` | `Allowed: false`, `Status.Reason` echoed |
| timeout / error / non-2xx| **fail-closed** (`Allowed: false`)       |

Combined with `failurePolicy: Fail` on the `ValidatingWebhookConfiguration`,
this makes the webhook's default posture **deny on uncertainty**.

## Install (Helm)

```sh
# Pre-req: cert-manager is installed and a (Cluster)Issuer exists.
kubectl create namespace trustforge

helm install tf-admission-webhook ./helm \
  --namespace trustforge \
  --set image.tag=0.1.0 \
  --set certManager.enabled=true \
  --set certManager.issuerRef.name=selfsigned-issuer \
  --set certManager.issuerRef.kind=ClusterIssuer
```

To opt a namespace into TrustForge enforcement:

```sh
kubectl label namespace my-app trustforge.dev/enabled=true
```

## Uninstall

```sh
helm uninstall tf-admission-webhook -n trustforge
kubectl delete namespace trustforge
```

If pod creation is blocked because the webhook is unhealthy, remove the
`ValidatingWebhookConfiguration` first:

```sh
kubectl delete validatingwebhookconfiguration tf-admission-webhook
```

## Build the image

```sh
docker build -t ghcr.io/nugit-tech/tf-admission-webhook:0.1.0 .
```

The multi-stage `Dockerfile` produces an alpine-based image of roughly
~10 MB containing a static `CGO_ENABLED=0` binary.

## Local development

```sh
go vet ./...
go test ./...
go build -o /tmp/tf-admission-webhook ./cmd
```

## Troubleshooting

### Webhook logs

```sh
kubectl -n trustforge logs deploy/tf-admission-webhook -f
```

The webhook logs every daemon error with the offending namespace/name.

### Audit AdmissionReview traffic

Increase API-server audit verbosity, or attach a debug pod:

```sh
kubectl -n trustforge run -it --rm curl --image=curlimages/curl -- \
  /bin/sh -c 'curl -kv https://tf-admission-webhook.trustforge.svc/healthz'
```

### Failing closed unexpectedly

1. Confirm the daemon URL is reachable from the webhook pod
   (`--daemon-url` / `daemon.url` Helm value).
2. Check the daemon's `/v1/decide` returns valid JSON with a `decision`
   field. The webhook does not interpret HTTP-level errors as allows.
3. Inspect the request shape the webhook synthesised by lowering log
   verbosity in the daemon and looking at the `actor / action / target`
   tuple.

### Locked out of cluster pod creation

If a misconfigured webhook is blocking all admissions, delete the
`ValidatingWebhookConfiguration` (above). The chart's namespace selector
defaults to `trustforge.dev/enabled=true` to limit blast radius.

## Files

- `cmd/main.go` — webhook HTTPS server.
- `cmd/main_test.go` — unit tests with a mock daemon.
- `Dockerfile` — multi-stage build, alpine runtime.
- `helm/` — Helm chart with cert-manager integration.
- `manifests/example-policy.yaml` — standalone example
  `ValidatingWebhookConfiguration`.
