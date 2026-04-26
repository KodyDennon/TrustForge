// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// tf-pihole-policy — small HTTP sidecar that the Pi-hole lighttpd
// proxies admin queries to. Each incoming request is translated into
// a /v1/decide call against the local tf-daemon. The sidecar replies
// with HTTP 200 + a passthrough body on `decision: allow` and HTTP
// 403 with a JSON reason on anything else.
//
// The sidecar exposes a tiny additional endpoint:
//
//   GET  /healthz                — liveness for systemd / lighttpd.
//   POST /trustforge/decide      — direct decide passthrough (used by
//                                  the gravity hook and by external
//                                  tools that want to ask "would
//                                  Pi-hole gate this domain?").
//   *  /admin/api.php           — proxied through tf-daemon and, on
//   *  /admin/queries.php          allow, forwarded to the real Pi-hole
//   *  /admin/scripts/...           lighttpd backend at 127.0.0.1:80.
//
// On daemon error the sidecar fails closed (HTTP 503). The lighttpd
// config in ../../lighttpd/external.conf is the canonical wiring.
//
// Status: Draft (Phase 0). Not production-ready. The reference
// tf-daemon is not yet shipped; this binary is useful primarily for
// conformance testing against a mock daemon.
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
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

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

// Sidecar bundles config; injected for testability.
type Sidecar struct {
	DaemonURL    string
	BackendURL   string // real Pi-hole lighttpd backend
	ActorURI     string
	HTTPClient   *http.Client
	BackendProxy *httputil.ReverseProxy
}

// NewSidecar returns a configured sidecar. The backend URL is
// optional — when empty, allow-decisions return HTTP 200 with a
// minimal JSON body instead of proxying to a real Pi-hole.
func NewSidecar(daemonURL, backendURL, actorURI string) (*Sidecar, error) {
	s := &Sidecar{
		DaemonURL:  strings.TrimRight(daemonURL, "/"),
		BackendURL: strings.TrimRight(backendURL, "/"),
		ActorURI:   actorURI,
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	}
	if backendURL != "" {
		bu, err := url.Parse(backendURL)
		if err != nil {
			return nil, fmt.Errorf("backend url: %w", err)
		}
		s.BackendProxy = httputil.NewSingleHostReverseProxy(bu)
	}
	return s, nil
}

// ActionFromPath maps a Pi-hole admin URL onto a TrustForge action.
// Exported for tests.
func ActionFromPath(p string) string {
	switch {
	case strings.HasSuffix(p, "/api.php"):
		return "pihole.admin.api"
	case strings.HasSuffix(p, "/queries.php"):
		return "pihole.admin.queries"
	case strings.HasSuffix(p, "/gravity.php"):
		return "pihole.gravity.refresh"
	case strings.Contains(p, "/scripts/pi-hole/"):
		return "pihole.admin.script"
	default:
		return "pihole.admin.unknown"
	}
}

// callDaemon issues a /v1/decide call.
func (s *Sidecar) callDaemon(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.DaemonURL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	resp, err := s.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("daemon round-trip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon %d: %s", resp.StatusCode, string(raw))
	}
	var dr DecideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &dr, nil
}

// HandleAdmin gates an admin-pane request on a /v1/decide call.
func (s *Sidecar) HandleAdmin(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	if q := r.URL.RawQuery; q != "" {
		target = target + "?" + q
	}
	dr := DecideRequest{
		Actor:  s.ActorURI,
		Action: ActionFromPath(r.URL.Path),
		Target: target,
	}
	resp, err := s.callDaemon(r.Context(), dr)
	if err != nil {
		log.Printf("daemon error on %s: %v", r.URL.Path, err)
		http.Error(w, `{"error":"trustforge daemon unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if resp.Decision != "allow" {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision": resp.Decision,
			"reason":   resp.Reason,
		})
		return
	}
	if s.BackendProxy != nil {
		s.BackendProxy.ServeHTTP(w, r)
		return
	}
	// No backend configured: return a minimal allow envelope.
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"decision": "allow"})
}

// HandleDecidePassthrough exposes a /trustforge/decide endpoint so the
// gravity hook (and other CLI consumers) can ask the daemon directly
// without re-implementing the wire shape.
func (s *Sidecar) HandleDecidePassthrough(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var dr DecideRequest
	if err := json.NewDecoder(r.Body).Decode(&dr); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if dr.Actor == "" {
		dr.Actor = s.ActorURI
	}
	resp, err := s.callDaemon(r.Context(), dr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Healthz is a liveness probe. It does NOT call the daemon — by
// design, the sidecar should report "up" even when the daemon is
// down so systemd doesn't restart it in a useless loop.
func (s *Sidecar) Healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// Routes returns the configured ServeMux. Exported for tests.
func (s *Sidecar) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.Healthz)
	mux.HandleFunc("/trustforge/decide", s.HandleDecidePassthrough)
	mux.HandleFunc("/admin/api.php", s.HandleAdmin)
	mux.HandleFunc("/admin/queries.php", s.HandleAdmin)
	mux.HandleFunc("/admin/scripts/pi-hole/php/gravity.php", s.HandleAdmin)
	return mux
}

func main() {
	var (
		addr       = flag.String("addr", ":8788", "HTTP listen address")
		daemonURL  = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8787"), "tf-daemon base URL")
		backendURL = flag.String("backend", envOr("PIHOLE_BACKEND", ""), "real Pi-hole lighttpd backend (empty = no proxy)")
		actorURI   = flag.String("actor", envOr("TF_PIHOLE_ACTOR", "tf:actor:device:pihole/local"), "this Pi-hole's TrustForge actor URI")
	)
	flag.Parse()

	s, err := NewSidecar(*daemonURL, *backendURL, *actorURI)
	if err != nil {
		log.Fatalf("sidecar: %v", err)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("tf-pihole-policy listening on %s (daemon=%s backend=%s actor=%s)",
		*addr, *daemonURL, *backendURL, *actorURI)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
