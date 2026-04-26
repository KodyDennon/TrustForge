// Package trustforgeiris provides kataras/iris v12 middleware that gates
// inbound requests on the TrustForge daemon's `/v1/decide` endpoint.
package trustforgeiris

import (
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"

	"github.com/trustforge/trustforge"
)

// ContextKey is the iris context value key under which the TrustForge
// decision is stored on allow.
const ContextKey = "trustforge.decision"

// Config configures the iris middleware/handler.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses
	// `ctx.GetCurrentRoute().Path()` (iris's route pattern) when available.
	ActionFor func(ctx iris.Context) string
}

// Handler returns a default-configured iris handler.
func Handler() context.Handler {
	return HandlerWith(Config{Client: trustforge.NewClient("")})
}

// HandlerWith returns an iris handler bound to the supplied config.
func HandlerWith(cfg Config) context.Handler {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(ctx iris.Context) string {
			path := ""
			if r := ctx.GetCurrentRoute(); r != nil {
				path = r.Path()
			}
			if path == "" {
				path = ctx.Path()
			}
			return ctx.Method() + " " + path
		}
	}

	return func(ctx iris.Context) {
		r := ctx.Request()
		req := trustforge.DecideRequest{
			Action:        cfg.ActionFor(ctx),
			HostToken:     trustforge.ExtractBearer(r.Header.Get("Authorization"), r.Header.Get("X-TF-Token")),
			HostTokenKind: cfg.HostTokenKind,
			Target:        r.URL.RequestURI(),
			TraceID:       r.Header.Get("X-Trace-ID"),
		}
		resp, err := cfg.Client.Decide(r.Context(), req)
		if err != nil {
			if cfg.FailOpen && trustforge.IsTransportError(err) {
				ctx.Next()
				return
			}
			ctx.StatusCode(iris.StatusServiceUnavailable)
			_ = ctx.JSON(iris.Map{
				"error":  "tf_decide_unreachable",
				"detail": err.Error(),
			})
			return
		}

		switch {
		case resp.IsAllow():
			ctx.Values().Set(ContextKey, resp)
			ctx.Next()
		case resp.IsDeny():
			ctx.StatusCode(iris.StatusForbidden)
			_ = ctx.JSON(iris.Map{
				"error":       "tf_denied",
				"reason":      resp.Reason,
				"proof_id":    resp.ProofID,
				"danger_tags": resp.DangerTags,
			})
		case resp.IsApproval():
			ctx.StatusCode(iris.StatusAccepted)
			_ = ctx.JSON(iris.Map{
				"status":      "approval_required",
				"approval_id": resp.ApprovalID,
				"proof_id":    resp.ProofID,
				"reason":      resp.Reason,
			})
		default:
			ctx.StatusCode(iris.StatusBadGateway)
			_ = ctx.JSON(iris.Map{
				"error":    "tf_unknown_decision",
				"decision": resp.Decision,
			})
		}
	}
}

// Decision retrieves the TrustForge decision attached to the iris context.
func Decision(ctx iris.Context) *trustforge.DecideResponse {
	v := ctx.Values().Get(ContextKey)
	if v == nil {
		return nil
	}
	d, _ := v.(*trustforge.DecideResponse)
	return d
}
