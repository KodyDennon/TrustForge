// Package trustforgegrpc provides google.golang.org/grpc unary and stream
// server interceptors that gate inbound RPCs on the TrustForge daemon's
// `/v1/decide` endpoint.
//
// The interceptors map gRPC outcomes to the same semantic decisions used by
// every HTTP adapter:
//   - "allow"             -> RPC proceeds, decision attached to context
//   - "deny"              -> codes.PermissionDenied
//   - "approval_required" -> codes.FailedPrecondition (with reason in details)
//   - daemon unreachable  -> codes.Unavailable (or pass-through if FailOpen)
package trustforgegrpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/trustforge/trustforge"
)

type ctxKey struct{}

// DecisionFromContext returns the TrustForge decision attached to the RPC
// context by the unary or stream interceptor, or nil.
func DecisionFromContext(ctx context.Context) *trustforge.DecideResponse {
	v, _ := ctx.Value(ctxKey{}).(*trustforge.DecideResponse)
	return v
}

// Config configures the interceptors.
type Config struct {
	Client        *trustforge.Client
	HostTokenKind string
	FailOpen      bool
	// ActionFor overrides the default action string. Default uses the gRPC
	// full method name (e.g. `/pkg.Svc/Method`).
	ActionFor func(fullMethod string) string
}

func (cfg *Config) defaults() {
	if cfg.Client == nil {
		cfg.Client = trustforge.NewClient("")
	}
	if cfg.ActionFor == nil {
		cfg.ActionFor = func(m string) string { return "RPC " + m }
	}
}

func tokenFromMD(md metadata.MD) string {
	if vs := md.Get("authorization"); len(vs) > 0 {
		return trustforge.ExtractBearer(vs[0], "")
	}
	if vs := md.Get("x-tf-token"); len(vs) > 0 {
		return trustforge.ExtractBearer("", vs[0])
	}
	return ""
}

func traceFromMD(md metadata.MD) string {
	if vs := md.Get("x-trace-id"); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// decide is the shared decision path used by both unary and stream interceptors.
// Returns:
//   - newCtx: enriched context to forward (only meaningful on allow)
//   - err:    nil on allow; gRPC status error otherwise
func decide(ctx context.Context, cfg *Config, fullMethod string) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	req := trustforge.DecideRequest{
		Action:        cfg.ActionFor(fullMethod),
		HostToken:     tokenFromMD(md),
		HostTokenKind: cfg.HostTokenKind,
		Target:        fullMethod,
		TraceID:       traceFromMD(md),
	}
	resp, err := cfg.Client.Decide(ctx, req)
	if err != nil {
		if cfg.FailOpen && trustforge.IsTransportError(err) {
			return ctx, nil
		}
		return ctx, status.Errorf(codes.Unavailable, "tf_decide_unreachable: %s", err.Error())
	}

	switch {
	case resp.IsAllow():
		return context.WithValue(ctx, ctxKey{}, resp), nil
	case resp.IsDeny():
		return ctx, status.Errorf(codes.PermissionDenied, "tf_denied: %s (proof_id=%s tags=%s)",
			resp.Reason, resp.ProofID, strings.Join(resp.DangerTags, ","))
	case resp.IsApproval():
		return ctx, status.Errorf(codes.FailedPrecondition, "tf_approval_required: approval_id=%s reason=%s",
			resp.ApprovalID, resp.Reason)
	default:
		return ctx, status.Errorf(codes.Internal, "tf_unknown_decision: %s", resp.Decision)
	}
}

// UnaryServerInterceptor returns a default-configured unary interceptor.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return UnaryServerInterceptorWith(Config{})
}

// UnaryServerInterceptorWith returns a unary interceptor bound to the supplied
// config.
func UnaryServerInterceptorWith(cfg Config) grpc.UnaryServerInterceptor {
	cfg.defaults()
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		newCtx, err := decide(ctx, &cfg, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

// StreamServerInterceptor returns a default-configured stream interceptor.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return StreamServerInterceptorWith(Config{})
}

// StreamServerInterceptorWith returns a stream interceptor bound to the
// supplied config.
func StreamServerInterceptorWith(cfg Config) grpc.StreamServerInterceptor {
	cfg.defaults()
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx, err := decide(ss.Context(), &cfg, info.FullMethod)
		if err != nil {
			return err
		}
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: newCtx}
		return handler(srv, wrapped)
	}
}

// wrappedServerStream overrides Context() so downstream handlers see the
// TrustForge decision attached on allow.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context { return w.ctx }
