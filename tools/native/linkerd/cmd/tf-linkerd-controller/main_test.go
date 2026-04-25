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

// mockDaemon answers POST /v1/decide with the supplied DecideResponse.
func mockDaemon(reply DecideResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
}

func newServer(name, ns string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetUnstructuredContent(map[string]interface{}{
		"apiVersion": "policy.linkerd.io/v1beta1",
		"kind":       "Server",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": ns,
		},
		"spec": map[string]interface{}{
			"port": "http",
		},
	})
	return obj
}

func TestReconcileOne_AllowProducesAuthorization(t *testing.T) {
	d := mockDaemon(DecideResponse{
		Decision:   "allow",
		Identities: []string{"app.svc.cluster.local"},
		Reason:     "policy: app allowed",
	})
	defer d.Close()

	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		ServerGVR:              "ServerList",
		ServerAuthorizationGVR: "ServerAuthorizationList",
	}
	srv := newServer("example", "default")

	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, srv)

	r := &Reconciler{
		Client: client,
		Daemon: &DaemonClient{URL: d.URL, HTTP: http.DefaultClient},
	}

	if err := r.reconcileOne(context.Background(), srv); err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}

	got, err := client.Resource(ServerAuthorizationGVR).Namespace("default").Get(context.Background(), "example-trustforge", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected created ServerAuthorization: %v", err)
	}
	ids, found, err := unstructured.NestedStringSlice(got.Object, "spec", "client", "meshTLS", "identities")
	if err != nil || !found {
		t.Fatalf("identities missing: found=%v err=%v", found, err)
	}
	if len(ids) != 1 || ids[0] != "app.svc.cluster.local" {
		t.Fatalf("bad identities: %v", ids)
	}
	annot := got.GetAnnotations()
	if annot["trustforge.io/managed"] != "true" {
		t.Fatalf("missing managed annotation: %v", annot)
	}
}

func TestReconcileOne_DaemonErrorFailsClosed(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		ServerGVR:              "ServerList",
		ServerAuthorizationGVR: "ServerAuthorizationList",
	}
	srv := newServer("example", "default")
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, srv)

	r := &Reconciler{
		Client: client,
		// Port 1 is unused: daemon round-trip will fail.
		Daemon: &DaemonClient{URL: "http://127.0.0.1:1", HTTP: http.DefaultClient},
	}

	if err := r.reconcileOne(context.Background(), srv); err != nil {
		t.Fatalf("reconcileOne: %v", err)
	}

	got, err := client.Resource(ServerAuthorizationGVR).Namespace("default").Get(context.Background(), "example-trustforge", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected created ServerAuthorization: %v", err)
	}
	ids, _, _ := unstructured.NestedStringSlice(got.Object, "spec", "client", "meshTLS", "identities")
	if len(ids) != 0 {
		t.Fatalf("fail-closed expected empty identities, got %v", ids)
	}
}
