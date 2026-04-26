// Package trustforge provides a minimal HTTP client for the local tf-daemon
// `/v1/decide` endpoint. It is shared by every Go HTTP framework adapter
// (net/http, chi, gin, echo, fiber, iris, buffalo, grpc) so they all speak
// the same wire format.
//
// The wire format mirrors the Rust `tf-decide-client` crate and the Python
// `trustforge_client.TrustForge` class. See `crates/adapters/tf-decide-client`
// and `tools/adapters/python/trustforge-fastapi` for the canonical
// implementations.
package trustforge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultDaemonURL is the standard local tf-daemon HTTP bridge URL.
const DefaultDaemonURL = "http://127.0.0.1:8787"

// DecideRequest is the JSON body POSTed to `{daemon}/v1/decide`.
//
// Field order, names, and `omitempty` semantics must match the Rust and
// Python clients exactly.
type DecideRequest struct {
	Actor          string                 `json:"actor,omitempty"`
	HostToken      string                 `json:"host_token,omitempty"`
	HostTokenKind  string                 `json:"host_token_kind,omitempty"`
	Action         string                 `json:"action"`
	Target         string                 `json:"target,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	TraceID        string                 `json:"trace_id,omitempty"`
}

// DecideResponse is the JSON body returned from `/v1/decide`.
type DecideResponse struct {
	Decision       string   `json:"decision"`
	Reason         string   `json:"reason,omitempty"`
	ApprovalID     string   `json:"approval_id,omitempty"`
	ProofID        string   `json:"proof_id,omitempty"`
	ActorResolved  string   `json:"actor_resolved,omitempty"`
	TrustLevel     string   `json:"trust_level,omitempty"`
	AuthorityMode  string   `json:"authority_mode,omitempty"`
	DangerTags     []string `json:"danger_tags,omitempty"`
}

// IsAllow reports whether the decision string is "allow" (case-insensitive).
func (r *DecideResponse) IsAllow() bool {
	return strings.EqualFold(r.Decision, "allow")
}

// IsDeny reports whether the decision string is "deny" (case-insensitive).
func (r *DecideResponse) IsDeny() bool {
	return strings.EqualFold(r.Decision, "deny")
}

// IsApproval reports whether the decision string is one of
// "approval", "approval_required", or "approval-required".
func (r *DecideResponse) IsApproval() bool {
	s := strings.ToLower(r.Decision)
	return s == "approval" || s == "approval_required" || s == "approval-required"
}

// Client is a thread-safe HTTP client bound to one tf-daemon URL.
//
// The zero value is not usable; construct via NewClient.
type Client struct {
	daemonURL  string
	adminToken string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client (e.g. to set a custom
// timeout or transport).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithAdminToken sets the bearer token sent on every request.
func WithAdminToken(tok string) Option {
	return func(c *Client) { c.adminToken = tok }
}

// WithTimeout sets the request timeout on the default *http.Client. Ignored if
// WithHTTPClient is also passed.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if c.httpClient != nil {
			c.httpClient.Timeout = d
		}
	}
}

// NewClient builds a new Client. Empty daemonURL falls back to DefaultDaemonURL.
// Trailing slashes are trimmed.
func NewClient(daemonURL string, opts ...Option) *Client {
	if daemonURL == "" {
		daemonURL = DefaultDaemonURL
	}
	for strings.HasSuffix(daemonURL, "/") {
		daemonURL = daemonURL[:len(daemonURL)-1]
	}
	c := &Client{
		daemonURL:  daemonURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// DaemonURL returns the configured daemon URL (without trailing slash).
func (c *Client) DaemonURL() string { return c.daemonURL }

// Decide POSTs `req` to `{daemonURL}/v1/decide` and decodes the response.
//
// On non-2xx, returns a *DecideHTTPError; on transport errors, returns the raw
// error so callers can implement fail-open semantics.
func (c *Client) Decide(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	body, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("trustforge: marshal request: %w", err)
	}
	url := c.daemonURL + "/v1/decide"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("trustforge: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.adminToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("trustforge: transport: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("trustforge: read body: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		return nil, &DecideHTTPError{Status: resp.StatusCode, Body: string(respBody)}
	}

	var out DecideResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("trustforge: decode response: %w", err)
	}
	return &out, nil
}

// DecideHTTPError is returned when the daemon answers with a non-2xx status.
type DecideHTTPError struct {
	Status int
	Body   string
}

func (e *DecideHTTPError) Error() string {
	return fmt.Sprintf("trustforge: daemon returned %d: %s", e.Status, e.Body)
}

// IsTransportError reports whether err is a connection-level failure (and not
// an HTTP-level error). Adapters use this to decide whether to honour the
// `fail_open` flag.
func IsTransportError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *DecideHTTPError
	return !errors.As(err, &httpErr)
}

// ExtractBearer pulls a host token out of an Authorization or x-tf-token
// header value, stripping a leading "Bearer " (case-insensitive). Returns
// "" if neither is present.
func ExtractBearer(authzHeader, tfTokenHeader string) string {
	if authzHeader != "" {
		s := strings.TrimSpace(authzHeader)
		if len(s) >= 7 && strings.EqualFold(s[:7], "bearer ") {
			return strings.TrimSpace(s[7:])
		}
		return s
	}
	return strings.TrimSpace(tfTokenHeader)
}

// Options is the shared per-adapter configuration applied to every request.
type Options struct {
	// Action is the optional override for the action string. If empty, each
	// adapter computes its own (typically "METHOD /path").
	Action string
	// HostTokenKind is forwarded verbatim to the daemon.
	HostTokenKind string
	// FailOpen, when true, treats transport errors to the daemon as "allow"
	// rather than 503. HTTP-level errors still fail closed.
	FailOpen bool
}
