# tf-istio adapter

Two pieces that sit alongside Istio:

1. **`tf-istio-controller`** — a Go controller that watches Istio
   `AuthorizationPolicy` CRs, calls `tf-daemon`'s
   `/v1/policy/validate`, and writes the result back into
   `.status.conditions[type=TrustForgeValidated]`.
2. **Manifests** — a `TrustForgePolicy` CRD plus a
   `MutatingWebhookConfiguration` that injects a `tf-daemon` sidecar
   into pods labelled `trustforge.dev/inject=true`.

**Status:** Draft — Phase 0. Experimental, not production-ready. The
reference `tf-daemon` and the companion `tf-sidecar-injector` deployment
are not yet shipped.

## Install

### Prerequisites

- An Istio control plane (1.20+).
- `cert-manager` for webhook TLS.
- `kubectl`, `istioctl`.

### Steps

```sh
# 1. Install Istio with proxy includes (so the wasm/sidecar can see all
#    inbound ports your apps use).
istioctl install \
  --set values.global.proxy.includeInboundPorts="*"

# 2. Apply the TrustForgePolicy CRD + sidecar-injector webhook.
kubectl apply -f manifests/authorization-policy-trustforge.yaml
kubectl apply -f manifests/sidecar-injector.yaml

# 3. Build & deploy the controller (image build out of scope here):
go build -o tf-istio-controller ./cmd/tf-istio-controller
# ...containerise + Deployment manifest...

# 4. Opt a namespace in.
kubectl label namespace my-app trustforge.dev/enabled=true

# 5. Label workload pods so they get the tf-daemon sidecar.
kubectl label pod -n my-app web trustforge.dev/inject=true
```

After a few seconds the pod should show two containers
(`kubectl get pod -n my-app web -o jsonpath='{.spec.containers[*].name}'`),
and any `AuthorizationPolicy` you create will pick up a
`TrustForgeValidated` condition:

```sh
kubectl get authorizationpolicy -n my-app -o yaml | yq '.status.conditions'
```

## Observe decisions

Every `/v1/decide` and `/v1/policy/validate` call is recorded as a
TrustForge **proof event** by the daemon. To stream them:

```sh
# Inside the sidecar container of any TF-injected pod.
kubectl exec -n my-app deploy/web -c tf-daemon -- \
    tf-cli proof tail --format=jsonl
```

(See `crates/tf-proof/` once it lands; `tf-cli` is also Phase 0 only.)

## Uninstall

```sh
kubectl delete -f manifests/sidecar-injector.yaml
kubectl delete -f manifests/authorization-policy-trustforge.yaml
# Remove the controller Deployment.
```

## Files

- `cmd/tf-istio-controller/main.go` — controller entry point.
- `cmd/tf-istio-controller/main_test.go` — fake-client reconcile tests.
- `manifests/authorization-policy-trustforge.yaml` — `TrustForgePolicy`
  CRD + example AuthorizationPolicy generated from it.
- `manifests/sidecar-injector.yaml` —
  `MutatingWebhookConfiguration` that injects the `tf-daemon` sidecar.

## Local dev

```sh
go vet ./...
go test ./...
go build -o /tmp/tf-istio-controller ./cmd/tf-istio-controller
```

## Troubleshooting

| symptom                                        | likely cause                                                               |
|-----------------------------------------------|----------------------------------------------------------------------------|
| `AuthorizationPolicy` has no TF condition     | controller not running, or `--daemon-url` unreachable                      |
| Condition `Reason=DaemonError`                | tf-daemon down / wrong URL / network policy blocking                       |
| Pods missing `tf-daemon` sidecar              | namespace missing `trustforge.dev/enabled=true` label, or pod missing inject label |
| `MutatingWebhookConfiguration` rejects pods   | injector failurePolicy is `Ignore` by default — check controller logs       |
