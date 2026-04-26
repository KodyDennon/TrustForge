package trustforgeecho

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
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

func newApp(daemonURL string) *echo.Echo {
	e := echo.New()
	e.Use(MiddlewareWith(Config{Client: trustforge.NewClient(daemonURL)}))
	e.GET("/users/:id", func(c echo.Context) error {
		dec := Decision(c)
		if dec != nil {
			c.Response().Header().Set("X-TF-Decision", dec.Decision)
		}
		return c.String(200, "ok")
	})
	return e
}

func TestEchoAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	d := daemon("allow", &captured)
	defer d.Close()

	req := httptest.NewRequest("GET", "/users/42", nil)
	w := httptest.NewRecorder()
	newApp(d.URL).ServeHTTP(w, req)

	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("expected 200 ok, got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(captured.Action, ":id") {
		t.Fatalf("expected echo route pattern :id in action, got %q", captured.Action)
	}
}

func TestEchoDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	req := httptest.NewRequest("GET", "/users/1", nil)
	w := httptest.NewRecorder()
	newApp(d.URL).ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestEchoApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	req := httptest.NewRequest("GET", "/users/1", nil)
	w := httptest.NewRecorder()
	newApp(d.URL).ServeHTTP(w, req)
	if w.Code != 202 {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}
