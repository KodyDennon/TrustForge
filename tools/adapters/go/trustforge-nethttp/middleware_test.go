package trustforgenethttp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trustforge/trustforge"
)

func daemon(decision string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(trustforge.DecideResponse{
			Decision:   decision,
			Reason:     "test",
			ProofID:    "p",
			ApprovalID: "a",
		})
	}))
}

func runOnce(t *testing.T, decision, authz string) (*http.Response, string) {
	t.Helper()
	d := daemon(decision)
	defer d.Close()

	mw := MiddlewareWith(Config{Client: trustforge.NewClient(d.URL)})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dec := DecisionFromContext(r.Context()); dec != nil {
			w.Header().Set("X-TF-Decision", dec.Decision)
		}
		_, _ = w.Write([]byte("ok"))
	}))

	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/x", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestAllow(t *testing.T) {
	resp, body := runOnce(t, "allow", "Bearer t")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("expected 200 ok, got %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-TF-Decision") != "allow" {
		t.Fatalf("expected decision attached, got %q", resp.Header.Get("X-TF-Decision"))
	}
}

func TestDeny(t *testing.T) {
	resp, body := runOnce(t, "deny", "")
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "tf_denied") {
		t.Fatalf("expected tf_denied body, got %s", body)
	}
}

func TestApproval(t *testing.T) {
	resp, body := runOnce(t, "approval_required", "")
	if resp.StatusCode != 202 {
		t.Fatalf("expected 202, got %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "approval_required") {
		t.Fatalf("expected approval_required body, got %s", body)
	}
}

func TestFailOpen(t *testing.T) {
	mw := MiddlewareWith(Config{
		Client:   trustforge.NewClient("http://127.0.0.1:1"),
		FailOpen: true,
	})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("through"))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "through" {
		t.Fatalf("expected fail-open through, got %d %s", resp.StatusCode, body)
	}
}

func TestDaemonUnreachableFailClosed(t *testing.T) {
	mw := MiddlewareWith(Config{Client: trustforge.NewClient("http://127.0.0.1:1")})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("nope"))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503 fail-closed, got %d", resp.StatusCode)
	}
}
