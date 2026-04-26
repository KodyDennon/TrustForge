// SPDX-License-Identifier: Apache-2.0 OR MIT
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockDaemon(t *testing.T, want *DecideRequest, reply DecideResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		var got DecideRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if want != nil {
			*want = got
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
}

func TestActionFromPath_KnownEndpoints(t *testing.T) {
	cases := map[string]string{
		"/admin/api.php":                              "pihole.admin.api",
		"/admin/queries.php":                          "pihole.admin.queries",
		"/admin/scripts/pi-hole/php/gravity.php":      "pihole.gravity.refresh",
		"/admin/scripts/pi-hole/php/some-other.php":   "pihole.admin.script",
		"/something/else":                             "pihole.admin.unknown",
	}
	for in, want := range cases {
		if got := ActionFromPath(in); got != want {
			t.Errorf("ActionFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHandleAdmin_AllowReturnsMinimalEnvelope(t *testing.T) {
	d := mockDaemon(t, nil, DecideResponse{Decision: "allow"})
	defer d.Close()
	s, err := NewSidecar(d.URL, "", "tf:actor:device:pihole/test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api.php?summary", nil)
	s.HandleAdmin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"allow"`) {
		t.Fatalf("expected allow envelope, got %s", rec.Body.String())
	}
}

func TestHandleAdmin_DenyReturns403WithReason(t *testing.T) {
	d := mockDaemon(t, nil, DecideResponse{Decision: "deny", Reason: "after-hours admin"})
	defer d.Close()
	s, _ := NewSidecar(d.URL, "", "tf:actor:device:pihole/test")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/queries.php", nil)
	s.HandleAdmin(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "after-hours admin") {
		t.Fatalf("missing reason: %s", rec.Body.String())
	}
}

func TestHandleAdmin_DaemonDownIs503NotAllow(t *testing.T) {
	s, _ := NewSidecar("http://127.0.0.1:1", "", "tf:actor:device:pihole/test")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api.php", nil)
	s.HandleAdmin(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestHandleAdmin_BackendProxyForwardsOnAllow(t *testing.T) {
	// Mock pi-hole backend.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	d := mockDaemon(t, nil, DecideResponse{Decision: "allow"})
	defer d.Close()

	s, err := NewSidecar(d.URL, backend.URL, "tf:actor:device:pihole/test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api.php?stats", nil)
	s.HandleAdmin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Header().Get("X-Backend") != "yes" {
		t.Fatalf("backend header missing: %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), "backend-ok") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestHandleDecidePassthrough_HappyPath(t *testing.T) {
	var seen DecideRequest
	d := mockDaemon(t, &seen, DecideResponse{Decision: "allow"})
	defer d.Close()
	s, _ := NewSidecar(d.URL, "", "tf:actor:device:pihole/test")
	body, _ := json.Marshal(DecideRequest{Action: "pihole.gravity.refresh", Target: "resolver"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/trustforge/decide", bytes.NewReader(body))
	s.HandleDecidePassthrough(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if seen.Actor != "tf:actor:device:pihole/test" {
		t.Fatalf("default actor not applied: %+v", seen)
	}
}

func TestHandleDecidePassthrough_RejectsGet(t *testing.T) {
	s, _ := NewSidecar("http://127.0.0.1:1", "", "tf:actor:device:pihole/test")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/trustforge/decide", nil)
	s.HandleDecidePassthrough(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestHealthz_AlwaysOK(t *testing.T) {
	s, _ := NewSidecar("http://127.0.0.1:1", "", "tf:actor:device:pihole/test")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Healthz(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestRoutes_ReturnsMux(t *testing.T) {
	s, _ := NewSidecar("http://127.0.0.1:1", "", "tf:actor:device:pihole/test")
	mux := s.Routes()
	if mux == nil {
		t.Fatal("nil mux")
	}
	// Sanity: the healthz route is registered (a 200 doesn't depend on the daemon).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil).WithContext(context.Background())
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}
