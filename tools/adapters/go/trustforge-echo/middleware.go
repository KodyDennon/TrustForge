// Package trustforgeecho provides labstack/echo v4 middleware that gates
// inbound requests on the TrustForge daemon's `/v1/decide` endpoint.
package trustforgeecho

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/trustforge/trustforge"
)

// ContextKey is the echo.Context key under which the TrustForge decision is
// stored on allow.
const ContextKey = "trustforge.decision"

// Config configures the echo middleware.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses
	// `c.Path()` (echo's route pattern) when available.
	ActionFor func(c echo.Context) string
}

// Middleware returns a default-configured echo middleware.
func Middleware() echo.MiddlewareFunc {
	return MiddlewareWith(Config{Client: trustforge.NewClient("")})
}

// MiddlewareWith returns echo middleware bound to the supplied config.
func MiddlewareWith(cfg Config) echo.MiddlewareFunc {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(c echo.Context) string {
			path := c.Path()
			if path == "" {
				path = c.Request().URL.Path
			}
			return c.Request().Method + " " + path
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
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
				return c.JSON(http.StatusServiceUnavailable, echo.Map{
					"error":  "tf_decide_unreachable",
					"detail": err.Error(),
				})
			}

			switch {
			case resp.IsAllow():
				c.Set(ContextKey, resp)
				return next(c)
			case resp.IsDeny():
				return c.JSON(http.StatusForbidden, echo.Map{
					"error":       "tf_denied",
					"reason":      resp.Reason,
					"proof_id":    resp.ProofID,
					"danger_tags": resp.DangerTags,
				})
			case resp.IsApproval():
				return c.JSON(http.StatusAccepted, echo.Map{
					"status":      "approval_required",
					"approval_id": resp.ApprovalID,
					"proof_id":    resp.ProofID,
					"reason":      resp.Reason,
				})
			default:
				return c.JSON(http.StatusBadGateway, echo.Map{
					"error":    "tf_unknown_decision",
					"decision": resp.Decision,
				})
			}
		}
	}
}

// Decision retrieves the TrustForge decision attached to the echo.Context.
func Decision(c echo.Context) *trustforge.DecideResponse {
	v := c.Get(ContextKey)
	if v == nil {
		return nil
	}
	d, _ := v.(*trustforge.DecideResponse)
	return d
}
