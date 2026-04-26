package trustforgebuffalo

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobuffalo/buffalo"

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

func newApp(daemonURL string) *buffalo.App {
	app := buffalo.New(buffalo.Options{Env: "test"})
	app.Use(MiddlewareWith(Config{Client: trustforge.NewClient(daemonURL)}))
	app.GET("/users/{id}", func(c buffalo.Context) error {
		dec := Decision(c)
		if dec != nil {
			c.Response().Header().Set("X-TF-Decision", dec.Decision)
		}
		return c.Render(200, nil) // body via the writer below
	})
	return app
}

// We use a tiny inline handler that writes a body without the renderer to keep
// the test independent of buffalo's plush template engine.
func newAppWithBody(daemonURL string) *buffalo.App {
	app := buffalo.New(buffalo.Options{Env: "test"})
	app.Use(MiddlewareWith(Config{Client: trustforge.NewClient(daemonURL)}))
	app.GET("/users/{id}", func(c buffalo.Context) error {
		dec := Decision(c)
		if dec != nil {
			c.Response().Header().Set("X-TF-Decision", dec.Decision)
		}
		_, _ = c.Response().Write([]byte("ok"))
		return nil
	})
	return app
}

func TestBuffaloAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	d := daemon("allow", &captured)
	defer d.Close()

	app := newAppWithBody(d.URL)
	srv := httptest.NewServer(app)
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
	if resp.Header.Get("X-TF-Decision") != "allow" {
		t.Fatalf("expected decision attached, got %q", resp.Header.Get("X-TF-Decision"))
	}
}

func TestBuffaloDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	srv := httptest.NewServer(newAppWithBody(d.URL))
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

func TestBuffaloApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	srv := httptest.NewServer(newAppWithBody(d.URL))
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

// Compile-time guard: ensure newApp is referenced (avoids unused warning when
// only newAppWithBody is exercised).
var _ = newApp
