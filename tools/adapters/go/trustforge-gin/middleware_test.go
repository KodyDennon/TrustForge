package trustforgegin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/trustforge/trustforge"
)

func init() {
	gin.SetMode(gin.TestMode)
}

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

func newRouter(daemonURL string) *gin.Engine {
	r := gin.New()
	r.Use(MiddlewareWith(Config{Client: trustforge.NewClient(daemonURL)}))
	r.GET("/users/:id", func(c *gin.Context) {
		dec := Decision(c)
		if dec != nil {
			c.Header("X-TF-Decision", dec.Decision)
		}
		c.String(200, "ok")
	})
	return r
}

func do(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestGinAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	d := daemon("allow", &captured)
	defer d.Close()

	w := do(newRouter(d.URL), "GET", "/users/42")
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("expected 200 ok, got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(captured.Action, ":id") {
		t.Fatalf("expected gin route pattern :id in action, got %q", captured.Action)
	}
	if w.Header().Get("X-TF-Decision") != "allow" {
		t.Fatalf("expected decision attached, got %q", w.Header().Get("X-TF-Decision"))
	}
}

func TestGinDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	w := do(newRouter(d.URL), "GET", "/users/1")
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestGinApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	w := do(newRouter(d.URL), "GET", "/users/1")
	if w.Code != 202 {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}
