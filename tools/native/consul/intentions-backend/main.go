// SPDX-License-Identifier: Apache-2.0
//
// tf-consul-intentions-backend — an HTTP service that answers Consul
// Connect intention checks by delegating each one to the local
// TrustForge daemon (`tf-daemon`).
//
// Consul does not natively support an external authoriser, so this
// binary fronts the (unofficial but widely-used) intentions HTTP
// shape:
//
//	POST /v1/intention/check
//	{ "Source": "<svc>", "Destination": "<svc>" }
//
// and proxies it as:
//
//	POST <tf-daemon>/v1/decide
//	{ "actor": "<source>", "action": "consul.connect.dial", "target": "<destination>" }
//
// On `decision: "allow"` it answers `{"Allowed": true}` (matching the
// Consul HTTP API contract); anything else is `{"Allowed": false}`
// with the daemon's reason in `Reason`. Daemon errors fail closed.
//
// Status: Draft (Phase 0). Not production-ready. This binary is
// exercised against the working reference daemon, but remains mock-tested.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// IntentionCheckRequest is the wire shape Consul (or a compatible
// caller) POSTs to /v1/intention/check.
type IntentionCheckRequest struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

// IntentionCheckResponse is what we hand back. Consul's native
// /v1/connect/intentions/check uses query params and `{"Allowed": bool}`
// — we accept both the JSON body and the query-string form.
type IntentionCheckResponse struct {
	Allowed bool   `json:"Allowed"`
	Reason  string `json:"Reason,omitempty"`
}

// DecideRequest is the wire shape of POST <tf-daemon>/v1/decide.
type DecideRequest struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// DecideResponse is what tf-daemon returns.
type DecideResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// Backend bundles config; injected for testability.
type Backend struct {
	DaemonURL  string
	HTTPClient *http.Client
}

// NewBackend returns a Backend with the supplied daemon URL.
func NewBackend(daemonURL string) *Backend {
	return &Backend{
		DaemonURL:  daemonURL,
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	}
}

// callDaemon issues a /v1/decide call.
func (b *Backend) callDaemon(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal decide request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.DaemonURL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := b.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("daemon round-trip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon returned %d: %s", resp.StatusCode, string(raw))
	}
	var dr DecideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode decide response: %w", err)
	}
	return &dr, nil
}

// parseRequest pulls (source, destination) from either a JSON body or
// `?source=...&destination=...` query string. Exported indirectly via
// tests.
func parseRequest(r *http.Request) (IntentionCheckRequest, error) {
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		return IntentionCheckRequest{
			Source:      q.Get("source"),
			Destination: q.Get("destination"),
		}, nil
	}
	if r.Method != http.MethodPost {
		return IntentionCheckRequest{}, fmt.Errorf("method %s not allowed", r.Method)
	}
	var ir IntentionCheckRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ir, fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return ir, nil
	}
	if err := json.Unmarshal(body, &ir); err != nil {
		return ir, fmt.Errorf("decode body: %w", err)
	}
	return ir, nil
}

// HandleCheck is the core HTTP handler exported for tests.
func (b *Backend) HandleCheck(rw http.ResponseWriter, r *http.Request) {
	ir, err := parseRequest(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if ir.Source == "" || ir.Destination == "" {
		http.Error(rw, "Source and Destination are required", http.StatusBadRequest)
		return
	}
	dr := DecideRequest{
		Actor:  ir.Source,
		Action: "consul.connect.dial",
		Target: ir.Destination,
	}
	out, err := b.callDaemon(r.Context(), dr)
	if err != nil {
		log.Printf("daemon error: %v", err)
		writeJSON(rw, http.StatusOK, IntentionCheckResponse{
			Allowed: false,
			Reason:  "TrustForge daemon unavailable: " + err.Error(),
		})
		return
	}
	if out.Decision == "allow" {
		writeJSON(rw, http.StatusOK, IntentionCheckResponse{Allowed: true, Reason: out.Reason})
		return
	}
	reason := out.Reason
	if reason == "" {
		reason = "TrustForge denied intention"
	}
	writeJSON(rw, http.StatusOK, IntentionCheckResponse{Allowed: false, Reason: reason})
}

func writeJSON(rw http.ResponseWriter, code int, v interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}

func healthz(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("ok"))
}

func main() {
	var (
		addr      = flag.String("addr", ":9000", "HTTP listen address")
		daemonURL = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8765"), "tf-daemon base URL")
	)
	flag.Parse()

	b := NewBackend(*daemonURL)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/intention/check", b.HandleCheck)
	// Consul also speaks /v1/connect/intentions/check.
	mux.HandleFunc("/v1/connect/intentions/check", b.HandleCheck)
	mux.HandleFunc("/healthz", healthz)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("tf-consul-intentions-backend listening on %s (daemon=%s)", *addr, *daemonURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
