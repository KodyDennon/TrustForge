// SPDX-License-Identifier: Apache-2.0
//
// sync.go — talks to the TrustForge daemon's /v1/decide endpoint to
// obtain start, pledge-class, and unveil-path verdicts.
//
// The supervisor must call /v1/decide three times per child:
//
//   1. kind="pledge_start"     payload contains the child argv, env,
//                              and the requested promises set. The
//                              daemon may shrink the promise set.
//   2. kind="pledge_unveil"    one call per UnveilEntry. The daemon
//                              may downgrade or deny the perm.
//   3. kind="pledge_outcome"   reports exit status (best-effort, the
//                              child may have died ungracefully).
//
// Errors from the daemon are funneled through the FailOpen knob:
// when true, the supervisor proceeds with the requested set; when
// false (the default), the call is rejected.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DecideRequest struct {
	V        int      `json:"v"`
	Kind     string   `json:"kind"`
	Platform string   `json:"platform"`
	Name     string   `json:"name"`
	Argv     []string `json:"argv,omitempty"`
	Env      []string `json:"env,omitempty"`
	Promises []string `json:"promises,omitempty"`
	ExecProm []string `json:"exec_promises,omitempty"`
	Path     string   `json:"path,omitempty"`
	Perm     string   `json:"perm,omitempty"`
	PID      int      `json:"pid,omitempty"`
	ExitCode int      `json:"exit_code,omitempty"`
	Signal   int      `json:"signal,omitempty"`
}

// DecideResponse is the daemon's reply. Result==0 means allow; any
// non-zero value means deny (the value is informational, typically
// EACCES).
//
// For pledge_start the daemon may also return an *adjusted* promise
// set in Promises / ExecPromises; the supervisor will use the
// intersection of requested and adjusted.
//
// For pledge_unveil the daemon may downgrade Perm.
type DecideResponse struct {
	Result   int32    `json:"result"`
	Reason   string   `json:"reason,omitempty"`
	Promises []string `json:"promises,omitempty"`
	ExecProm []string `json:"exec_promises,omitempty"`
	Perm     string   `json:"perm,omitempty"`
}

// DecisionClient is the interface used by Supervisor; tests inject a
// fake.
type DecisionClient interface {
	Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error)
}

type httpDecisionClient struct {
	url    string
	client *http.Client
}

func newDecisionClient(daemon string, timeoutMs int) (DecisionClient, error) {
	u, err := url.Parse(daemon)
	if err != nil {
		return nil, fmt.Errorf("invalid --daemon %q: %w", daemon, err)
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if u.Scheme == "unix" || strings.HasPrefix(daemon, "/") {
		path := daemon
		if u.Scheme == "unix" {
			path = u.Path
		}
		tr := &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", path, timeout)
			},
		}
		return &httpDecisionClient{
			url:    "http://unix/v1/decide",
			client: &http.Client{Transport: tr, Timeout: timeout},
		}, nil
	}
	return &httpDecisionClient{
		url:    daemon,
		client: &http.Client{Timeout: timeout},
	}, nil
}

func (h *httpDecisionClient) Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error) {
	if req.V == 0 {
		req.V = 1
	}
	if req.Platform == "" {
		req.Platform = "openbsd-pledge"
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned %d", resp.StatusCode)
	}
	var dr DecideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	return &dr, nil
}

// intersectStrings returns the elements of want that are also present
// in mask. If mask is nil, want is returned unchanged.
func intersectStrings(want, mask []string) []string {
	if mask == nil {
		return want
	}
	allow := make(map[string]struct{}, len(mask))
	for _, m := range mask {
		allow[m] = struct{}{}
	}
	out := make([]string, 0, len(want))
	for _, w := range want {
		if _, ok := allow[w]; ok {
			out = append(out, w)
		}
	}
	return out
}

// intersectPerm computes the intersection of two unveil perm
// strings (subset of "rwxc"). Empty string is "no access" and acts
// as the absorbing element.
func intersectPerm(a, b string) string {
	if a == "" || b == "" {
		return ""
	}
	out := make([]byte, 0, 4)
	for _, c := range a {
		if strings.ContainsRune(b, c) {
			out = append(out, byte(c))
		}
	}
	return string(out)
}

// ErrDenied is returned by the supervisor when the daemon denies an
// allow-required call (start or unveil) and FailOpen is false.
var ErrDenied = errors.New("trustforge daemon denied the request")
