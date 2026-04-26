package trustforgegrpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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
			DangerTags: []string{"t1"},
		})
	}))
}

func ctxWithAuth(tok string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+tok, "x-trace-id", "trace-1")
	return metadata.NewIncomingContext(context.Background(), md)
}

func runUnary(t *testing.T, decision string, captureReq *trustforge.DecideRequest) (interface{}, error) {
	t.Helper()
	d := daemon(decision, captureReq)
	defer d.Close()

	intc := UnaryServerInterceptorWith(Config{Client: trustforge.NewClient(d.URL)})
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		dec := DecisionFromContext(ctx)
		if dec == nil {
			t.Errorf("expected decision attached on allow")
		}
		return "ok", nil
	}
	return intc(ctxWithAuth("tk"), "in", info, handler)
}

func TestUnaryAllow(t *testing.T) {
	var captured trustforge.DecideRequest
	resp, err := runUnary(t, "allow", &captured)
	if err != nil {
		t.Fatal(err)
	}
	if resp != "ok" {
		t.Fatalf("expected ok, got %v", resp)
	}
	if !strings.Contains(captured.Action, "/pkg.Svc/Method") {
		t.Fatalf("expected method in action, got %q", captured.Action)
	}
	if captured.HostToken != "tk" {
		t.Fatalf("expected token, got %q", captured.HostToken)
	}
	if captured.TraceID != "trace-1" {
		t.Fatalf("expected trace, got %q", captured.TraceID)
	}
}

func TestUnaryDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	intc := UnaryServerInterceptorWith(Config{Client: trustforge.NewClient(d.URL)})
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}
	_, err := intc(context.Background(), "in", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called on deny")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected deny error")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %s", status.Code(err))
	}
}

func TestUnaryApproval(t *testing.T) {
	d := daemon("approval_required", nil)
	defer d.Close()
	intc := UnaryServerInterceptorWith(Config{Client: trustforge.NewClient(d.URL)})
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}
	_, err := intc(context.Background(), "in", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called on approval")
		return nil, nil
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %s", status.Code(err))
	}
}

func TestUnaryDaemonUnreachable(t *testing.T) {
	intc := UnaryServerInterceptorWith(Config{Client: trustforge.NewClient("http://127.0.0.1:1")})
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}
	_, err := intc(context.Background(), "in", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called when daemon unreachable")
		return nil, nil
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %s", status.Code(err))
	}
}

func TestUnaryFailOpen(t *testing.T) {
	intc := UnaryServerInterceptorWith(Config{
		Client:   trustforge.NewClient("http://127.0.0.1:1"),
		FailOpen: true,
	})
	info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Svc/Method"}
	called := false
	_, err := intc(context.Background(), "in", info, func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "passthrough", nil
	})
	if err != nil {
		t.Fatalf("expected nil error in fail-open, got %v", err)
	}
	if !called {
		t.Fatal("expected handler to be called in fail-open")
	}
}

// stubServerStream is a minimal grpc.ServerStream used to drive the stream
// interceptor without spinning up a real server.
type stubServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *stubServerStream) Context() context.Context { return s.ctx }

func TestStreamAllow(t *testing.T) {
	d := daemon("allow", nil)
	defer d.Close()
	intc := StreamServerInterceptorWith(Config{Client: trustforge.NewClient(d.URL)})
	info := &grpc.StreamServerInfo{FullMethod: "/pkg.Svc/Stream"}

	called := false
	err := intc(nil, &stubServerStream{ctx: ctxWithAuth("tk")}, info, func(_ interface{}, ss grpc.ServerStream) error {
		called = true
		if DecisionFromContext(ss.Context()) == nil {
			t.Errorf("expected decision attached")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("handler never ran")
	}
}

func TestStreamDeny(t *testing.T) {
	d := daemon("deny", nil)
	defer d.Close()
	intc := StreamServerInterceptorWith(Config{Client: trustforge.NewClient(d.URL)})
	info := &grpc.StreamServerInfo{FullMethod: "/pkg.Svc/Stream"}
	err := intc(nil, &stubServerStream{ctx: context.Background()}, info, func(_ interface{}, _ grpc.ServerStream) error {
		t.Fatal("handler should not be called on deny")
		return nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %s", status.Code(err))
	}
}
