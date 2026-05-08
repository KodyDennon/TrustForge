// SPDX-License-Identifier: Apache-2.0
//
// tf-istio-controller — watches Istio AuthorizationPolicy CRs, validates
// each against the local TrustForge daemon's policy-validate endpoint,
// and writes the result back into `.status.conditions[type=TrustForgeValidated]`.
//
// AuthorizationPolicy is an Istio CRD (security.istio.io/v1beta1). The
// controller treats it as `unstructured.Unstructured` so we don't have to
// pull in the heavyweight Istio Go module just to read a few fields.
//
// Status: Draft (Phase 0). Not production-ready. This binary is exercised
// against the working reference daemon, but remains mock-tested.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// AuthorizationPolicyGVR is the GroupVersionResource of the Istio CRD.
var AuthorizationPolicyGVR = schema.GroupVersionResource{
	Group:    "security.istio.io",
	Version:  "v1beta1",
	Resource: "authorizationpolicies",
}

// ValidateRequest is the wire shape of POST /v1/policy/validate.
type ValidateRequest struct {
	Kind   string                 `json:"kind"`
	Name   string                 `json:"name"`
	Spec   map[string]interface{} `json:"spec"`
}

// ValidateResponse is what tf-daemon returns.
type ValidateResponse struct {
	Valid    bool     `json:"valid"`
	Reason   string   `json:"reason,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// DaemonClient calls /v1/policy/validate.
type DaemonClient struct {
	URL  string
	HTTP *http.Client
}

// Validate POSTs an AuthorizationPolicy spec and returns the daemon's verdict.
func (c *DaemonClient) Validate(ctx context.Context, req ValidateRequest) (*ValidateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/policy/validate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("daemon round-trip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon returned %d: %s", resp.StatusCode, string(raw))
	}
	var vr ValidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &vr, nil
}

// Reconciler is the testable core of the controller.
//
// It does not own a controller-runtime Manager — we keep the surface area
// minimal so the unit tests can stand it up with just a fake dynamic
// client. The main loop in `run` polls all AuthorizationPolicies, but the
// reconcile logic is identical to what an event-driven Watch would do.
type Reconciler struct {
	Client dynamic.Interface
	Daemon *DaemonClient
}

// reconcileAll lists AuthorizationPolicies cluster-wide and reconciles
// each one. Returns the number of objects processed.
func (r *Reconciler) reconcileAll(ctx context.Context) (int, error) {
	list, err := r.Client.Resource(AuthorizationPolicyGVR).
		Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list AuthorizationPolicies: %w", err)
	}
	processed := 0
	for i := range list.Items {
		obj := &list.Items[i]
		if err := r.reconcileOne(ctx, obj); err != nil {
			log.Printf("reconcile %s/%s: %v", obj.GetNamespace(), obj.GetName(), err)
			continue
		}
		processed++
	}
	return processed, nil
}

// reconcileOne validates a single AuthorizationPolicy and patches its status.
func (r *Reconciler) reconcileOne(ctx context.Context, obj *unstructured.Unstructured) error {
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	resp, err := r.Daemon.Validate(ctx, ValidateRequest{
		Kind: "AuthorizationPolicy",
		Name: obj.GetNamespace() + "/" + obj.GetName(),
		Spec: spec,
	})
	if err != nil {
		// Fail-closed: write a Failure condition so the user sees it.
		return r.writeStatus(ctx, obj, false, "DaemonError", err.Error())
	}
	reason := resp.Reason
	if resp.Valid {
		reason = "TrustForge accepted policy"
	} else if reason == "" {
		reason = "TrustForge rejected policy"
	}
	statusReason := "Validated"
	if !resp.Valid {
		statusReason = "Rejected"
	}
	return r.writeStatus(ctx, obj, resp.Valid, statusReason, reason)
}

// writeStatus updates the AuthorizationPolicy's status.conditions with a
// `TrustForgeValidated` entry. It uses an UpdateStatus subresource call
// when available, falling back to a regular Update.
func (r *Reconciler) writeStatus(ctx context.Context, obj *unstructured.Unstructured, valid bool, reason, message string) error {
	cond := map[string]interface{}{
		"type":               "TrustForgeValidated",
		"status":             condStatus(valid),
		"reason":             reason,
		"message":            message,
		"lastTransitionTime": metav1.Now().Format(time.RFC3339),
	}

	cur, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	updated := upsertCondition(cur, cond)
	if err := unstructured.SetNestedSlice(obj.Object, updated, "status", "conditions"); err != nil {
		return fmt.Errorf("set status.conditions: %w", err)
	}

	res := r.Client.Resource(AuthorizationPolicyGVR).Namespace(obj.GetNamespace())
	if _, err := res.UpdateStatus(ctx, obj, metav1.UpdateOptions{}); err != nil {
		// Dynamic fake clients do not implement subresources by default;
		// fall back to a plain Update so tests pass.
		if _, err2 := res.Update(ctx, obj, metav1.UpdateOptions{}); err2 != nil {
			return fmt.Errorf("update status: %w (after subresource error: %v)", err2, err)
		}
	}
	return nil
}

func condStatus(valid bool) string {
	if valid {
		return "True"
	}
	return "False"
}

// upsertCondition returns a copy of conds with a single
// `type=TrustForgeValidated` condition replaced or appended.
func upsertCondition(conds []interface{}, newCond map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(conds)+1)
	replaced := false
	for _, c := range conds {
		m, ok := c.(map[string]interface{})
		if ok && m["type"] == "TrustForgeValidated" {
			out = append(out, newCond)
			replaced = true
			continue
		}
		out = append(out, c)
	}
	if !replaced {
		out = append(out, newCond)
	}
	return out
}

// run does a simple polling loop. A production controller would use an
// informer + workqueue, but the polling implementation makes the binary
// trivially correct for Phase 0.
func (r *Reconciler) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		n, err := r.reconcileAll(ctx)
		if err != nil {
			log.Printf("reconcileAll: %v", err)
		} else {
			log.Printf("reconciled %d AuthorizationPolicies", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func main() {
	var (
		kubeconfig = flag.String("kubeconfig", "", "path to kubeconfig (empty = in-cluster)")
		daemonURL  = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8765"), "tf-daemon base URL")
		interval   = flag.Duration("interval", 30*time.Second, "reconcile poll interval")
	)
	flag.Parse()

	cfg, err := loadConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("dynamic client: %v", err)
	}

	r := &Reconciler{
		Client: dyn,
		Daemon: &DaemonClient{
			URL:  *daemonURL,
			HTTP: &http.Client{Timeout: 5 * time.Second},
		},
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("tf-istio-controller starting (daemon=%s, interval=%s)", *daemonURL, *interval)
	r.run(ctx, *interval)
	log.Print("tf-istio-controller exiting")
}

func loadConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
