// Package trustforgebuffalo provides gobuffalo/buffalo middleware that gates
// inbound requests on the TrustForge daemon's `/v1/decide` endpoint.
package trustforgebuffalo

import (
	"net/http"

	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/buffalo/render"

	"github.com/trustforge/trustforge"
)

// ContextKey is the buffalo.Context value key under which the TrustForge
// decision is stored on allow.
const ContextKey = "trustforge.decision"

// Config configures the buffalo middleware.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses
	// the matched buffalo route info if available, falling back to
	// `request.URL.Path`.
	ActionFor func(c buffalo.Context) string
}

// Middleware returns a default-configured buffalo middleware.
func Middleware(next buffalo.Handler) buffalo.Handler {
	return MiddlewareWith(Config{Client: trustforge.NewClient("")})(next)
}

// MiddlewareWith returns buffalo middleware bound to the supplied config.
func MiddlewareWith(cfg Config) buffalo.MiddlewareFunc {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(c buffalo.Context) string {
			r := c.Request()
			path := r.URL.Path
			if ri, ok := c.Value("current_route").(buffalo.RouteInfo); ok && ri.Path != "" {
				path = ri.Path
			}
			return r.Method + " " + path
		}
	}
	return func(next buffalo.Handler) buffalo.Handler {
		return func(c buffalo.Context) error {
			r := c.Request()
			req := trustforge.DecideRequest{
				Action:        cfg.ActionFor(c),
				HostToken:     trustforge.ExtractBearer(r.Header.Get("Authorization"), r.Header.Get("X-TF-Token")),
				HostTokenKind: cfg.HostTokenKind,
				Target:        r.URL.RequestURI(),
				TraceID:       r.Header.Get("X-Trace-ID"),
			}
			resp, err := cfg.Client.Decide(r.Context(), req)
			if err != nil {
				if cfg.FailOpen && trustforge.IsTransportError(err) {
					return next(c)
				}
				return c.Render(http.StatusServiceUnavailable, render.JSON(map[string]any{
					"error":  "tf_decide_unreachable",
					"detail": err.Error(),
				}))
			}

			switch {
			case resp.IsAllow():
				c.Set(ContextKey, resp)
				return next(c)
			case resp.IsDeny():
				return c.Render(http.StatusForbidden, render.JSON(map[string]any{
					"error":       "tf_denied",
					"reason":      resp.Reason,
					"proof_id":    resp.ProofID,
					"danger_tags": resp.DangerTags,
				}))
			case resp.IsApproval():
				return c.Render(http.StatusAccepted, render.JSON(map[string]any{
					"status":      "approval_required",
					"approval_id": resp.ApprovalID,
					"proof_id":    resp.ProofID,
					"reason":      resp.Reason,
				}))
			default:
				return c.Render(http.StatusBadGateway, render.JSON(map[string]any{
					"error":    "tf_unknown_decision",
					"decision": resp.Decision,
				}))
			}
		}
	}
}

// Decision retrieves the TrustForge decision attached to the buffalo.Context.
func Decision(c buffalo.Context) *trustforge.DecideResponse {
	v := c.Value(ContextKey)
	if v == nil {
		return nil
	}
	d, _ := v.(*trustforge.DecideResponse)
	return d
}
