// SPDX-License-Identifier: Apache-2.0
//
// tf-k8s-admission-webhook — TrustForge ValidatingAdmissionWebhook.
//
// On every AdmissionReview the webhook calls the local tf-daemon
//
//	POST /v1/decide
//	{
//	  "actor":  "<ServiceAccount>",
//	  "action": "k8s.<verb>.<resource>",
//	  "target": "<namespace>/<name>"
//	}
//
// and returns AdmissionResponse{Allowed:true} on `decision:"allow"`,
// or Allowed:false + Result.Reason on `deny`. Anything else fails CLOSED.
//
// Status: Draft (Phase 0). Not production-ready. The reference tf-daemon
// is not yet shipped; this binary is useful primarily for conformance
// testing against a mock daemon.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DecideRequest is the wire-shape of POST /v1/decide.
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

// Webhook bundles config; injected for testability.
type Webhook struct {
	DaemonURL  string
	HTTPClient *http.Client
}

// NewWebhook returns a Webhook with the supplied daemon URL and a default
// short-timeout HTTP client.
func NewWebhook(daemonURL string) *Webhook {
	return &Webhook{
		DaemonURL: daemonURL,
		HTTPClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// callDaemon sends a DecideRequest and returns the parsed DecideResponse.
func (w *Webhook) callDaemon(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal decide request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, w.DaemonURL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := w.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("daemon round-trip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var dr DecideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode decide response: %w", err)
	}
	return &dr, nil
}

// buildDecideRequest extracts actor / action / target from an
// AdmissionRequest.
//
// actor   — ServiceAccount of the requesting principal (UserInfo.Username
// is typically of the form `system:serviceaccount:<ns>:<name>`).
// action  — `k8s.<verb>.<resource>` (e.g. `k8s.create.pods`).
// target  — `<namespace>/<name>` (or just `<name>` for cluster-scoped).
func buildDecideRequest(ar *admissionv1.AdmissionRequest) DecideRequest {
	target := ar.Name
	if ar.Namespace != "" {
		target = ar.Namespace + "/" + ar.Name
	}
	resource := ar.Resource.Resource
	if resource == "" {
		resource = ar.Kind.Kind
	}
	return DecideRequest{
		Actor:  ar.UserInfo.Username,
		Action: fmt.Sprintf("k8s.%s.%s", strings.ToLower(string(ar.Operation)), strings.ToLower(resource)),
		Target: target,
	}
}

// HandleAdmissionReview is the core HTTP handler. It is exported for tests.
func (w *Webhook) HandleAdmissionReview(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(rw, "decode AdmissionReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(rw, "AdmissionReview.Request is nil", http.StatusBadRequest)
		return
	}

	resp := w.decide(r.Context(), review.Request)
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: resp,
	}
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(out); err != nil {
		log.Printf("encode response: %v", err)
	}
}

// decide builds the daemon request, calls /v1/decide, and translates the
// result into an AdmissionResponse. Anything other than `decision:"allow"`
// is a DENY (fail-closed).
func (w *Webhook) decide(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	dr := buildDecideRequest(req)
	out, err := w.callDaemon(ctx, dr)
	if err != nil {
		log.Printf("daemon error for %s/%s: %v", req.Namespace, req.Name, err)
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: "TrustForge daemon unavailable: " + err.Error(),
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			},
		}
	}
	if out.Decision == "allow" {
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}
	reason := out.Reason
	if reason == "" {
		reason = "TrustForge denied request"
	}
	return &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: reason,
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		},
	}
}

// healthz is a liveness probe.
func healthz(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("ok"))
}

func main() {
	var (
		addr      = flag.String("addr", ":8443", "HTTPS listen address")
		certFile  = flag.String("tls-cert", "/etc/tf-webhook/tls/tls.crt", "TLS certificate path")
		keyFile   = flag.String("tls-key", "/etc/tf-webhook/tls/tls.key", "TLS key path")
		daemonURL = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8765"), "tf-daemon base URL")
	)
	flag.Parse()

	wh := NewWebhook(*daemonURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/admit", wh.HandleAdmissionReview)
	mux.HandleFunc("/healthz", healthz)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("tf-k8s-admission-webhook listening on %s (daemon=%s)", *addr, *daemonURL)
	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
