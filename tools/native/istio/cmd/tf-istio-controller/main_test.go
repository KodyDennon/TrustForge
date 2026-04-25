// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// mockDaemon spins up an HTTP test server that always returns `reply`.
func mockDaemon(t *testing.T, reply ValidateResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy/validate" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
}

// makePolicy returns a representative AuthorizationPolicy.
func makePolicy(ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "security.istio.io",
		Version: "v1beta1",
		Kind:    "AuthorizationPolicy",
	})
	u.SetNamespace(ns)
	u.SetName(name)
	_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{
		"action": "ALLOW",
		"rules": []interface{}{
			map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"source": map[string]interface{}{
							"principals": []interface{}{"cluster.local/ns/default/sa/web"},
						},
					},
				},
			},
		},
	}, "spec")
	return u
}

// fakeClientWith returns a fake dynamic client preloaded with `objs`.
// We register the GVR -> Kind mapping the fake client needs.
func fakeClientWith(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvrToList := map[schema.GroupVersionResource]string{
		AuthorizationPolicyGVR: "AuthorizationPolicyList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToList, objs...)
}

func TestReconcileOne_AcceptsValidPolicy(t *testing.T) {
	srv := mockDaemon(t, ValidateResponse{Valid: true})
	defer srv.Close()

	pol := makePolicy("default", "web-allow")
	cli := fakeClientWith(pol)

	r := &Reconciler{
		Client: cli,
		Daemon: &DaemonClient{URL: srv.URL, HTTP: srv.Client()},
	}

	if err := r.reconcileOne(context.Background(), pol); err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}

	got, err := cli.Resource(AuthorizationPolicyGVR).
		Namespace("default").
		Get(context.Background(), "web-allow", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	conds, _, _ := unstructured.NestedSlice(got.Object, "status", "conditions")
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}
	c := conds[0].(map[string]interface{})
	if c["type"] != "TrustForgeValidated" || c["status"] != "True" {
		t.Fatalf("bad condition: %+v", c)
	}
}

func TestReconcileOne_RejectsInvalidPolicy(t *testing.T) {
	srv := mockDaemon(t, ValidateResponse{Valid: false, Reason: "selector matches none"})
	defer srv.Close()

	pol := makePolicy("default", "bad")
	cli := fakeClientWith(pol)

	r := &Reconciler{
		Client: cli,
		Daemon: &DaemonClient{URL: srv.URL, HTTP: srv.Client()},
	}
	if err := r.reconcileOne(context.Background(), pol); err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}

	got, _ := cli.Resource(AuthorizationPolicyGVR).
		Namespace("default").
		Get(context.Background(), "bad", metav1.GetOptions{})
	conds, _, _ := unstructured.NestedSlice(got.Object, "status", "conditions")
	c := conds[0].(map[string]interface{})
	if c["status"] != "False" {
		t.Fatalf("expected status=False, got %v", c["status"])
	}
	if c["message"] != "selector matches none" {
		t.Fatalf("expected daemon reason in message, got %q", c["message"])
	}
}

func TestReconcileOne_FailClosedOnDaemonError(t *testing.T) {
	pol := makePolicy("default", "x")
	cli := fakeClientWith(pol)

	r := &Reconciler{
		Client: cli,
		Daemon: &DaemonClient{URL: "http://127.0.0.1:1", HTTP: &http.Client{}},
	}
	if err := r.reconcileOne(context.Background(), pol); err != nil {
		t.Fatalf("reconcileOne should write a failure status, not error: %v", err)
	}

	got, _ := cli.Resource(AuthorizationPolicyGVR).
		Namespace("default").
		Get(context.Background(), "x", metav1.GetOptions{})
	conds, _, _ := unstructured.NestedSlice(got.Object, "status", "conditions")
	c := conds[0].(map[string]interface{})
	if c["status"] != "False" || c["reason"] != "DaemonError" {
		t.Fatalf("expected DaemonError condition, got %+v", c)
	}
}

func TestReconcileAll_ProcessesEvery(t *testing.T) {
	srv := mockDaemon(t, ValidateResponse{Valid: true})
	defer srv.Close()

	cli := fakeClientWith(
		makePolicy("default", "a"),
		makePolicy("ns2", "b"),
		makePolicy("ns2", "c"),
	)
	r := &Reconciler{
		Client: cli,
		Daemon: &DaemonClient{URL: srv.URL, HTTP: srv.Client()},
	}
	n, err := r.reconcileAll(context.Background())
	if err != nil {
		t.Fatalf("reconcileAll: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 reconciled, got %d", n)
	}
}

func TestUpsertCondition_ReplacesExisting(t *testing.T) {
	conds := []interface{}{
		map[string]interface{}{"type": "Other", "status": "True"},
		map[string]interface{}{"type": "TrustForgeValidated", "status": "False"},
	}
	out := upsertCondition(conds, map[string]interface{}{"type": "TrustForgeValidated", "status": "True"})
	if len(out) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(out))
	}
	got := out[1].(map[string]interface{})
	if got["status"] != "True" {
		t.Fatalf("expected replacement, got %+v", got)
	}
}

func TestUpsertCondition_AppendsWhenAbsent(t *testing.T) {
	out := upsertCondition(nil, map[string]interface{}{"type": "TrustForgeValidated", "status": "True"})
	if len(out) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(out))
	}
}
