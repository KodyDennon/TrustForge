// Package trustforgenethttp provides stdlib net/http middleware that gates
// inbound requests on the TrustForge daemon's `/v1/decide` endpoint.
//
// Drop Middleware (or MiddlewareWith) into any net/http server. Every request
// will:
//   1. extract a host token from Authorization or x-tf-token,
//   2. POST to tf-daemon's /v1/decide,
//   3. on "allow"  -> attach the decision to the request context and forward,
//   4. on "deny"   -> respond 403,
//   5. on "approval_required" -> respond 202,
//   6. on transport error    -> respond 503 (or fail-open if configured).
package trustforgenethttp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/trustforge/trustforge"
)

type ctxKey struct{}

// DecisionFromContext retrieves the TrustForge decision attached to the
// request by Middleware. Returns nil if no decision is present.
func DecisionFromContext(ctx context.Context) *trustforge.DecideResponse {
	v, _ := ctx.Value(ctxKey{}).(*trustforge.DecideResponse)
	return v
}

// Config configures the middleware.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor lets callers override the default `METHOD /path` action string.
	ActionFor func(r *http.Request) string
}

// Middleware returns a default-configured middleware that talks to a tf-daemon
// at the default URL (http://127.0.0.1:8787).
func Middleware(next http.Handler) http.Handler {
	return MiddlewareWith(Config{Client: trustforge.NewClient("")})(next)
}

// MiddlewareWith returns middleware bound to the supplied config.
func MiddlewareWith(cfg Config) func(http.Handler) http.Handler {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(r *http.Request) string { return r.Method + " " + r.URL.Path }
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
