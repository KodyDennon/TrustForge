// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// tf-tailscale-sync — long-running Go sidecar that listens for
// Tailscale node events on the local API and consults the local
// tf-daemon (POST /v1/decide) before allowing each new connection.
//
// The Tailscale daemon (tailscaled) exposes a "local API" at
// /var/run/tailscale/tailscaled.sock (or %ProgramData% on Windows). It
// answers JSON GETs on /localapi/v0/status and a streaming
// /localapi/v0/watch-ipn-bus that emits one JSON event per node /
// peer change. Public Tailscale clients (the `tailscale` CLI, the
// taildrop helper, etc.) all use this socket.
//
// The upstream `tailscale.com/client/tailscale` Go package wraps that
// socket. We do not import it here for two reasons:
//
//   1. Pulling tailscale.com into our build closure brings ~80 MB of
//      transitive dependencies (Wireguard, BoringTun, magicsock, etc.)
//      which is outsized for a thin sidecar that only needs three
//      endpoints.
//   2. The TrustForge build is offline-first; CI does not have
//      module-proxy access during integration tests.
//
// Instead we hand-roll the small subset of the local API we care
// about. The wire shape matches what `tailscale.com/client/tailscale`
// uses internally (see its `client.go` for the canonical paths).
//
// On every peer-update event the sidecar:
//
//   1. Reads the peer's NodeKey, Hostname, OS, User, and TailscaleIPs.
//   2. POSTs /v1/decide to tf-daemon with:
//        actor  = tf:actor:host:tailscale/<nodekey-prefix>
//        action = tailscale.peer.connect
//        target = <our hostname>
//   3. On `decision: deny` it issues a `tailscale set --deny=<nodekey>`
//      via the local API's `prefs` endpoint (effectively a peer drop).
//   4. On `decision: allow` it does nothing (default Tailscale
//      behaviour is to accept the peer).
//
// The sidecar also exposes a small HTTP endpoint
// (POST /trustforge/ssh/auth) that Tailscale SSH's `OnAuthRequest`
// hook can call. See examples/sshconfig.example.
//
// Status: Draft (Phase 0). Not production-ready. The reference
// tf-daemon exists as a working reference; this binary remains useful primarily for
// conformance testing against a mock daemon.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
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

// Peer is the relevant subset of a Tailscale Status.Peer.
type Peer struct {
	NodeKey       string   `json:"PublicKey"`
	HostName      string   `json:"HostName"`
	OS            string   `json:"OS"`
	UserID        int64    `json:"UserID"`
	TailscaleIPs  []string `json:"TailscaleIPs"`
	Online        bool     `json:"Online"`
	LastSeen      string   `json:"LastSeen,omitempty"`
}

// Status is the relevant subset of a Tailscale Status.
type Status struct {
	BackendState string           `json:"BackendState"`
	Self         *Peer            `json:"Self"`
	Peer         map[string]*Peer `json:"Peer"`
}

// LocalClient speaks the Tailscale local API over the unix socket.
type LocalClient struct {
	SocketPath string
	HTTPClient *http.Client
}

// NewLocalClient returns a client wired to the platform's default
// tailscaled socket. Override SocketPath for tests or non-default
// installs.
func NewLocalClient() *LocalClient {
	socket := defaultSocketPath()
	return &LocalClient{
		SocketPath: socket,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
			Timeout: 10 * time.Second,
		},
	}
}

func defaultSocketPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/run/tailscaled.socket"
	case "windows":
		// On Windows tailscaled exposes a named pipe, not a unix
		// socket; this binary will not work as-is on Windows.
		return ""
	default:
		return "/var/run/tailscale/tailscaled.sock"
	}
}

// get is a small helper that issues a GET against the local API.
func (c *LocalClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("local-api get %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("local-api %s: %d %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

// Status returns the current Tailscale status.
func (c *LocalClient) Status(ctx context.Context) (*Status, error) {
	body, err := c.get(ctx, "/localapi/v0/status")
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return &s, nil
}

// WatchIPNBus streams JSON events from /localapi/v0/watch-ipn-bus.
// The handler is called for each event; return an error to stop.
func (c *LocalClient) WatchIPNBus(ctx context.Context, handle func(event []byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/watch-ipn-bus", nil)
	if err != nil {
		return err
	}
	// Use a per-request client without timeout (this stream is long-lived).
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.SocketPath)
		},
	}
	streamer := &http.Client{Transport: tr}
	resp, err := streamer.Do(req)
	if err != nil {
		return fmt.Errorf("watch-ipn-bus: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("watch-ipn-bus: %d %s", resp.StatusCode, string(raw))
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if err := handle(scanner.Bytes()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// Decider asks tf-daemon /v1/decide.
type Decider struct {
	DaemonURL  string
	HTTPClient *http.Client
}

func NewDecider(daemonURL string) *Decider {
	return &Decider{
		DaemonURL:  strings.TrimRight(daemonURL, "/"),
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	}
}

func (d *Decider) Decide(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.DaemonURL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	resp, err := d.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon %d: %s", resp.StatusCode, string(raw))
	}
	var dr DecideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	return &dr, nil
}

func main() {
	var (
		daemonURL  = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8787"), "tf-daemon base URL")
		sshAddr    = flag.String("ssh-addr", envOr("TF_TAILSCALE_SSH_ADDR", "127.0.0.1:8789"), "listen for the Tailscale-SSH OnAuthRequest hook")
		failClosed = flag.Bool("fail-closed", true, "if true, daemon errors are treated as deny")
		ourHost    = flag.String("our-host", envOr("TF_TAILSCALE_HOST", mustHostname()), "this node's hostname (becomes the decide.target)")
		socket     = flag.String("tailscale-socket", envOr("TS_SOCKET", defaultSocketPath()), "tailscaled local API socket path")
	)
	flag.Parse()

	dec := NewDecider(*daemonURL)
	tc := NewLocalClient()
	if *socket != "" {
		tc.SocketPath = *socket
	}

	// SSH auth-request HTTP endpoint runs in a goroutine.
	go runSSHAuthListener(*sshAddr, dec, *ourHost, *failClosed)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("tf-tailscale-sync started; daemon=%s tailscaled=%s ssh-listener=%s",
		*daemonURL, tc.SocketPath, *sshAddr)

	if err := runWatcher(ctx, tc, dec, *ourHost, *failClosed); err != nil {
		log.Fatalf("watcher: %v", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func mustHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return h
}
