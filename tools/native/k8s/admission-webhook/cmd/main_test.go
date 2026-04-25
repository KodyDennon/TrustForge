// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	authnv1 "k8s.io/api/authentication/v1"
)

// mockDaemon returns a httptest.Server that records the last DecideRequest
// it received and replies with the supplied DecideResponse.
func mockDaemon(t *testing.T, want *DecideRequest, reply DecideResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var got DecideRequest
		if err := json.Unmarshal(body, &got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if want != nil {
			*want = got
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
}

// makeReview wraps a typical AdmissionRequest in an AdmissionReview.
func makeReview() *admissionv1.AdmissionReview {
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid-1"),
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Kind: "Pod", Version: "v1"},
			Resource: metav1.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			Namespace: "default",
			Name:      "demo-pod",
			UserInfo: authnv1.UserInfo{
				Username: "system:serviceaccount:default:demo-sa",
			},
		},
	}
}

// helper to silence unused-import lint when GVK helpers are not used
var _ = schema.GroupVersionKind{}

func TestBuildDecideRequest_PodCreate(t *testing.T) {
	r := makeReview().Request
	got := buildDecideRequest(r)
	want := DecideRequest{
		Actor:  "system:serviceaccount:default:demo-sa",
		Action: "k8s.create.pods",
		Target: "default/demo-pod",
	}
	if got != want {
		t.Fatalf("buildDecideRequest mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestHandleAdmissionReview_Allow(t *testing.T) {
	var seen DecideRequest
	d := mockDaemon(t, &seen, DecideResponse{Decision: "allow"})
	defer d.Close()

	wh := NewWebhook(d.URL)
	review := makeReview()
	body, _ := json.Marshal(review)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admit", bytes.NewReader(body))

	wh.HandleAdmissionReview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Response == nil {
		t.Fatal("nil response")
	}
	if !out.Response.Allowed {
		t.Fatalf("expected Allowed=true, got %+v", out.Response)
	}
	if seen.Action != "k8s.create.pods" || seen.Actor != "system:serviceaccount:default:demo-sa" || seen.Target != "default/demo-pod" {
		t.Fatalf("daemon saw wrong fields: %+v", seen)
	}
	if out.Response.UID != "test-uid-1" {
		t.Fatalf("UID not echoed: got %q", out.Response.UID)
	}
}

func TestHandleAdmissionReview_Deny(t *testing.T) {
	d := mockDaemon(t, nil, DecideResponse{Decision: "deny", Reason: "policy: pod label missing"})
	defer d.Close()

	wh := NewWebhook(d.URL)
	body, _ := json.Marshal(makeReview())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admit", bytes.NewReader(body))

	wh.HandleAdmissionReview(rec, req)

	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response.Allowed {
		t.Fatal("expected Allowed=false on deny")
	}
	if out.Response.Result == nil || !strings.Contains(out.Response.Result.Message, "policy: pod label missing") {
		t.Fatalf("expected reason in Result.Message, got %+v", out.Response.Result)
	}
}

func TestHandleAdmissionReview_FailClosedOnDaemonError(t *testing.T) {
	// Point at a port that is closed.
	wh := NewWebhook("http://127.0.0.1:1") // port 1 is reserved/unused
	body, _ := json.Marshal(makeReview())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admit", bytes.NewReader(body))

	wh.HandleAdmissionReview(rec, req)

	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response.Allowed {
		t.Fatal("expected fail-closed (Allowed=false) when daemon is unreachable")
	}
}

func TestHandleAdmissionReview_RejectsGet(t *testing.T) {
	wh := NewWebhook("http://127.0.0.1:1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admit", nil)
	wh.HandleAdmissionReview(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
