// Package trustforgefiber provides gofiber/fiber v2 middleware that gates
// inbound requests on the TrustForge daemon's `/v1/decide` endpoint.
//
// Note: fiber is built on fasthttp, not net/http. This adapter uses
// `c.Context()` to get a context.Context for the upstream daemon call so the
// shared trustforge.Client (which uses net/http) still works.
package trustforgefiber

import (
	"github.com/gofiber/fiber/v2"
	"github.com/trustforge/trustforge"
)

// LocalsKey is the fiber.Ctx Locals key under which the TrustForge decision
// is stored on allow.
const LocalsKey = "trustforge.decision"

// Config configures the fiber middleware.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses
	// `c.Route().Path` (fiber's route pattern) when available.
	ActionFor func(c *fiber.Ctx) string
}

// New returns a default-configured fiber middleware handler.
func New() fiber.Handler {
	return NewWith(Config{Client: trustforge.NewClient("")})
}

// NewWith returns fiber middleware bound to the supplied config.
func NewWith(cfg Config) fiber.Handler {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(c *fiber.Ctx) string {
			path := ""
			if rt := c.Route(); rt != nil {
				path = rt.Path
			}
			if path == "" {
				path = c.Path()
			}
			return c.Method() + " " + path
		}
	}

	return func(c *fiber.Ctx) error {
		req := trustforge.DecideRequest{
			Action:        cfg.ActionFor(c),
			HostToken:     trustforge.ExtractBearer(c.Get("Authorization"), c.Get("X-TF-Token")),
			HostTokenKind: cfg.HostTokenKind,
			Target:        c.OriginalURL(),
			TraceID:       c.Get("X-Trace-ID"),
		}
		resp, err := cfg.Client.Decide(c.UserContext(), req)
		if err != nil {
			if cfg.FailOpen && trustforge.IsTransportError(err) {
				return c.Next()
			}
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error":  "tf_decide_unreachable",
				"detail": err.Error(),
			})
		}

		switch {
		case resp.IsAllow():
			c.Locals(LocalsKey, resp)
			return c.Next()
		case resp.IsDeny():
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":       "tf_denied",
				"reason":      resp.Reason,
				"proof_id":    resp.ProofID,
				"danger_tags": resp.DangerTags,
			})
		case resp.IsApproval():
			return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
				"status":      "approval_required",
				"approval_id": resp.ApprovalID,
				"proof_id":    resp.ProofID,
				"reason":      resp.Reason,
			})
		default:
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
				"error":    "tf_unknown_decision",
				"decision": resp.Decision,
			})
		}
	}
}

// Decision retrieves the TrustForge decision attached to the fiber context.
func Decision(c *fiber.Ctx) *trustforge.DecideResponse {
	v := c.Locals(LocalsKey)
	if v == nil {
		return nil
	}
	d, _ := v.(*trustforge.DecideResponse)
	return d
}
