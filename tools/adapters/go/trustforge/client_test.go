package trustforge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockDaemon(t *testing.T, want DecideResponse, capture *DecideRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/decide" {
			t.Errorf("expected /v1/decide path, got %s", r.URL.Path)
		}
		if capture != nil {
			if err := json.NewDecoder(r.Body).Decode(capture); err != nil {
				t.Errorf("decode body: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
}

func TestDecideAllow(t *testing.T) {
	var captured DecideRequest
	srv := mockDaemon(t, DecideResponse{Decision: "allow", ProofID: "p1"}, &captured)
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.Decide(context.Background(), DecideRequest{
		Action:    "GET /api",
		HostToken: "tok",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !resp.IsAllow() || resp.ProofID != "p1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if captured.Action != "GET /api" || captured.HostToken != "tok" {
		t.Fatalf("captured request mismatch: %+v", captured)
	}
}

func TestDecideDeny(t *testing.T) {
	srv := mockDaemon(t, DecideResponse{Decision: "deny", Reason: "nope"}, nil)
	defer srv.Close()
	resp, err := NewClient(srv.URL).Decide(context.Background(), DecideRequest{Action: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsDeny() {
		t.Fatalf("expected deny, got %+v", resp)
	}
}

func TestDecideApproval(t *testing.T) {
	for _, d := range []string{"approval", "approval_required", "approval-required"} {
		srv := mockDaemon(t, DecideResponse{Decision: d, ApprovalID: "a"}, nil)
		resp, err := NewClient(srv.URL).Decide(context.Background(), DecideRequest{Action: "x"})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !resp.IsApproval() {
			t.Fatalf("expected approval for %q, got %+v", d, resp)
		}
	}
}

func TestDecideTransportError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1") // unreachable
	_, err := c.Decide(context.Background(), DecideRequest{Action: "x"})
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsTransportError(err) {
		t.Fatalf("expected transport error, got %v", err)
	}
}

func TestDecideHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL).Decide(context.Background(), DecideRequest{Action: "x"})
	if err == nil {
		t.Fatal("expected http error")
	}
	if IsTransportError(err) {
		t.Fatalf("expected non-transport error, got %v", err)
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct{ a, x, want string }{
		{"Bearer abc", "", "abc"},
		{"bearer xyz", "", "xyz"},
		{"raw", "", "raw"},
		{"", "tf-tok", "tf-tok"},
		{"", "", ""},
	}
	for _, c := range cases {
		got := ExtractBearer(c.a, c.x)
		if got != c.want {
			t.Errorf("ExtractBearer(%q,%q)=%q, want %q", c.a, c.x, got, c.want)
		}
	}
}

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com///")
	if !strings.HasSuffix(c.DaemonURL(), "example.com") {
		t.Fatalf("expected trimmed URL, got %q", c.DaemonURL())
	}
}
