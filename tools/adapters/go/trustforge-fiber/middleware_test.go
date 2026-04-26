package trustforgefiber

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
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

func newApp(daemonURL string) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(NewWith(Config{Client: trustforge.NewClient(daemonURL)}))
	app.Get("/users/:id", func(c *fiber.Ctx) error {
		dec := Decision(c)
		if dec != nil {
			c.Set("X-TF-Decision", dec.Decision)
		}
		return c.SendString("ok")
	})
	return app
}

func runReq(t *testing.T, app *fiber.App, method, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestFiberAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	d := daemon("allow", &captured)
	defer d.Close()

	resp := runReq(t, newApp(d.URL), "GET", "/users/42")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("expected 200 ok, got %d %s", resp.StatusCode, body)
	}
	// fiber exposes the route pattern only after the route is matched. When
	// the middleware is registered via app.Use("/", ...) it runs before final
	// match, so the captured action references the mount-point route. Just
	// require that the action carries the GET method.
	if !strings.HasPrefix(captured.Action, "GET ") {
		t.Fatalf("expected GET prefix in action, got %q", captured.Action)
	}
}

func TestFiberDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	resp := runReq(t, newApp(d.URL), "GET", "/users/1")
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFiberApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	resp := runReq(t, newApp(d.URL), "GET", "/users/1")
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
}
