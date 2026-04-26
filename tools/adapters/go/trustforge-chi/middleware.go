// Package trustforgechi provides go-chi/chi v5 middleware that gates inbound
// requests on the TrustForge daemon's `/v1/decide` endpoint.
//
// chi middleware has the same `func(http.Handler) http.Handler` signature as
// stdlib net/http, so this package mirrors the trustforge-nethttp adapter but
// also exposes a chi-friendly RouteContext-aware action override.
package trustforgechi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/trustforge/trustforge"
)

type ctxKey struct{}

// DecisionFromContext returns the TrustForge decision attached to the request
// by Middleware, or nil.
func DecisionFromContext(ctx context.Context) *trustforge.DecideResponse {
	v, _ := ctx.Value(ctxKey{}).(*trustforge.DecideResponse)
	return v
}

// Config configures the chi middleware.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses the chi
	// route pattern when available, falling back to URL.Path.
	ActionFor func(r *http.Request) string
}

// Middleware returns a default-configured chi middleware.
func Middleware(next http.Handler) http.Handler {
	return MiddlewareWith(Config{Client: trustforge.NewClient("")})(next)
}

// MiddlewareWith returns chi middleware bound to the supplied config.
func MiddlewareWith(cfg Config) func(http.Handler) http.Handler {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(r *http.Request) string {
			if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePattern() != "" {
				return r.Method + " " + rctx.RoutePattern()
			}
			return r.Method + " " + r.URL.Path
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req := trustforge.DecideRequest{
				Action:        cfg.ActionFor(r),
				HostToken:     trustforge.ExtractBearer(r.Header.Get("Authorization"), r.Header.Get("X-TF-Token")),
				HostTokenKind: cfg.HostTokenKind,
				Target:        r.URL.RequestURI(),
				TraceID:       r.Header.Get("X-Trace-ID"),
			}
			resp, err := cfg.Client.Decide(r.Context(), req)
			if err != nil {
				if cfg.FailOpen && trustforge.IsTransportError(err) {
					next.ServeHTTP(w, r)
					return
				}
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error":  "tf_decide_unreachable",
					"detail": err.Error(),
				})
				return
			}

			switch {
			case resp.IsAllow():
				ctx := context.WithValue(r.Context(), ctxKey{}, resp)
				next.ServeHTTP(w, r.WithContext(ctx))
			case resp.IsDeny():
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":       "tf_denied",
					"reason":      resp.Reason,
					"proof_id":    resp.ProofID,
					"danger_tags": resp.DangerTags,
				})
			case resp.IsApproval():
				writeJSON(w, http.StatusAccepted, map[string]any{
					"status":      "approval_required",
					"approval_id": resp.ApprovalID,
					"proof_id":    resp.ProofID,
					"reason":      resp.Reason,
				})
			default:
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error":    "tf_unknown_decision",
					"decision": resp.Decision,
				})
			}
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
