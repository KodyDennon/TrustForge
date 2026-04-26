package trustforgeiris

import (
	"encoding/json"
	"io"
	"net/http"
	stdhttptest "net/http/httptest"
	"strings"
	"testing"

	"github.com/kataras/iris/v12"

	"github.com/trustforge/trustforge"
)

func daemon(decision string, capture *trustforge.DecideRequest) *stdhttptest.Server {
	return stdhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// newApp builds an iris application wired through the adapter, then exposes it
// as a *stdhttptest.Server so we can drive it from a vanilla net/http client.
func newApp(t *testing.T, daemonURL string) *stdhttptest.Server {
	t.Helper()
	app := iris.New()
	app.Logger().SetLevel("disable")
	app.UseRouter(HandlerWith(Config{Client: trustforge.NewClient(daemonURL)}))
	app.Get("/users/{id}", func(ctx iris.Context) {
		dec := Decision(ctx)
		if dec != nil {
			ctx.Header("X-TF-Decision", dec.Decision)
		}
		_, _ = ctx.WriteString("ok")
	})
	if err := app.Build(); err != nil {
		t.Fatalf("iris build: %v", err)
	}
	return stdhttptest.NewServer(app)
}

func TestIrisAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	d := daemon("allow", &captured)
	defer d.Close()

	srv := newApp(t, d.URL)
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
	// iris exposes the route pattern after the route is matched. With
	// `UseRouter` the middleware runs during routing, so the action may carry
	// either the full pattern or the resolved URL path; both are acceptable.
	if !strings.Contains(captured.Action, "/users/") {
		t.Fatalf("expected /users/ in action, got %q", captured.Action)
	}
}

func TestIrisDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	srv := newApp(t, d.URL)
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

func TestIrisApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	srv := newApp(t, d.URL)
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
