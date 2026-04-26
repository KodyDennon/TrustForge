// Package trustforgegin provides gin-gonic/gin middleware that gates inbound
// requests on the TrustForge daemon's `/v1/decide` endpoint.
package trustforgegin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/trustforge/trustforge"
)

// ContextKey is the key under which the TrustForge decision is stored in
// gin.Context (use c.Get(ContextKey)).
const ContextKey = "trustforge.decision"

// Config configures the gin middleware.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses
	// `c.FullPath()` (gin's route pattern) when available.
	ActionFor func(c *gin.Context) string
}

// Middleware returns a default-configured gin middleware.
func Middleware() gin.HandlerFunc {
	return MiddlewareWith(Config{Client: trustforge.NewClient("")})
}

// MiddlewareWith returns gin middleware bound to the supplied config.
func MiddlewareWith(cfg Config) gin.HandlerFunc {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(c *gin.Context) string {
			path := c.FullPath()
			if path == "" {
				path = c.Request.URL.Path
			}
			return c.Request.Method + " " + path
		}
	}

	return func(c *gin.Context) {
		req := trustforge.DecideRequest{
			Action:        cfg.ActionFor(c),
			HostToken:     trustforge.ExtractBearer(c.GetHeader("Authorization"), c.GetHeader("X-TF-Token")),
			HostTokenKind: cfg.HostTokenKind,
			Target:        c.Request.URL.RequestURI(),
			TraceID:       c.GetHeader("X-Trace-ID"),
		}
		resp, err := cfg.Client.Decide(c.Request.Context(), req)
		if err != nil {
			if cfg.FailOpen && trustforge.IsTransportError(err) {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":  "tf_decide_unreachable",
				"detail": err.Error(),
			})
			return
		}

		switch {
		case resp.IsAllow():
			c.Set(ContextKey, resp)
			c.Next()
		case resp.IsDeny():
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":       "tf_denied",
				"reason":      resp.Reason,
				"proof_id":    resp.ProofID,
				"danger_tags": resp.DangerTags,
			})
		case resp.IsApproval():
			c.AbortWithStatusJSON(http.StatusAccepted, gin.H{
				"status":      "approval_required",
				"approval_id": resp.ApprovalID,
				"proof_id":    resp.ProofID,
				"reason":      resp.Reason,
			})
		default:
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
				"error":    "tf_unknown_decision",
				"decision": resp.Decision,
			})
		}
	}
}

// Decision retrieves the TrustForge decision attached to the gin.Context.
func Decision(c *gin.Context) *trustforge.DecideResponse {
	v, ok := c.Get(ContextKey)
	if !ok {
		return nil
	}
	d, _ := v.(*trustforge.DecideResponse)
	return d
}
