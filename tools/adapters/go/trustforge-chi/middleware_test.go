package trustforgechi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/trustforge/trustforge"
)

func daemon(decision string, capture *trustforge.DecideRequest) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			_ = json.NewDecoder(r.Body).Decode(capture)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(trustforge.DecideResponse{
			Decision:   decision,
			Reason:     "test",
			ProofID:    "p",
			ApprovalID: "a",
		})
	}))
}

func newRouter(d *httptest.Server, capture *trustforge.DecideRequest) *chi.Mux {
	r := chi.NewRouter()
	r.Use(MiddlewareWith(Config{Client: trustforge.NewClient(d.URL)}))
	r.Get("/users/{id}", func(w http.ResponseWriter, req *http.Request) {
		if dec := DecisionFromContext(req.Context()); dec != nil {
			w.Header().Set("X-TF-Decision", dec.Decision)
		}
		_, _ = w.Write([]byte("ok"))
	})
	_ = capture
	return r
}

func TestChiAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	d := daemon("allow", &captured)
	defer d.Close()
	srv := httptest.NewServer(newRouter(d, &captured))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/users/42")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("expected 200 ok, got %d %s", resp.StatusCode, body)
	}
	// chi exposes the route pattern only after the route is matched. Since
	// Middleware runs during routing (before final match), the action falls
	// back to the URL path. Either form is acceptable.
	if !strings.Contains(captured.Action, "/users/") {
		t.Fatalf("expected /users/ in action, got %q", captured.Action)
	}
}

func TestChiDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	srv := httptest.NewServer(newRouter(d, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/users/1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestChiApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	srv := httptest.NewServer(newRouter(d, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/users/1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
}
