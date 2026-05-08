// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// tf-unifi-sync — long-running Go daemon that polls a UniFi Network
// Controller and reconciles the controller's inventory of clients and
// devices with the local `.tf/` actor manifests.
//
// On each tick the daemon:
//
//  1. fetches /api/s/<site>/stat/sta and /api/s/<site>/stat/device
//     from the controller;
//  2. asks the local tf-daemon (POST /v1/decide) whether each newly
//     observed client/device is allowed onto the network;
//  3. emits a per-actor manifest into <out_dir>/clients/<mac>.yaml
//     so downstream tooling (and human reviewers) can see the
//     committed actor identity associated with each MAC;
//  4. logs an audit line per (mac, action, decision).
//
// The daemon does NOT push enforcement back into the controller; that
// belongs to the companion controller-plugin (see ../../controller-plugin).
// This binary is a *reconciler* — it produces ground-truth manifests
// that humans and audit pipelines treat as the source of identity for
// every host the controller has seen.
//
// The reference UniFi REST endpoints used here are the long-stable
// shapes documented in the community `unifi-go` library; we don't
// import it to keep this binary dependency-free, but the URLs and
// response field names match.
//
// Status: Draft (Phase 0). Not production-ready. The reference
// tf-daemon exists as a working reference; this binary remains useful primarily for
// conformance testing against a mock daemon.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
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

// Client is the relevant subset of /stat/sta we keep.
type Client struct {
	Mac      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	Network  string `json:"network,omitempty"`
	OUI      string `json:"oui,omitempty"`
	IsGuest  bool   `json:"is_guest,omitempty"`
}

// Device is the relevant subset of /stat/device we keep.
type Device struct {
	Mac     string `json:"mac"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	Model   string `json:"model,omitempty"`
	Adopted bool   `json:"adopted,omitempty"`
}

type listResponse[T any] struct {
	Meta struct {
		RC string `json:"rc"`
	} `json:"meta"`
	Data []T `json:"data"`
}

// UniFi is a thin REST client. We don't pull in any external library
// — the controller's HTTPS API surface is small enough to inline.
type UniFi struct {
	BaseURL    string
	Site       string
	Username   string
	Password   string
	HTTPClient *http.Client
}

// NewUniFi constructs a client and primes a cookie jar.
func NewUniFi(baseURL, site, username, password string, insecure bool) (*UniFi, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &UniFi{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Site:     site,
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Jar:       jar,
			Timeout:   10 * time.Second,
			Transport: tr,
		},
	}, nil
}

// Login authenticates via /api/login (classic Network Application) or
// /api/auth/login (UniFi OS). We try the UniFi OS shape first, then
// fall back; both responses set a session cookie via the jar.
func (u *UniFi) Login(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"username": u.Username, "password": u.Password})
	for _, path := range []string{"/api/auth/login", "/api/login"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.BaseURL+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("content-type", "application/json")
		resp, err := u.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			return nil
		}
	}
	return errors.New("login failed against both /api/auth/login and /api/login")
}

func (u *UniFi) sitePath() string {
	if strings.HasPrefix(u.BaseURL, "https://") || strings.HasPrefix(u.BaseURL, "http://") {
		// Network Application API: /api/s/<site>/...
		// UniFi OS proxy:        /proxy/network/api/s/<site>/...
		// We resolve at call time by trying the proxy path first.
	}
	return u.Site
}

// fetchList GETs a list endpoint and parses the meta/data envelope.
func fetchList[T any](ctx context.Context, u *UniFi, suffix string) ([]T, error) {
	for _, prefix := range []string{"/proxy/network/api/s/", "/api/s/"} {
		url := u.BaseURL + prefix + u.sitePath() + suffix
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := u.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var lr listResponse[T]
		if err := json.Unmarshal(raw, &lr); err != nil {
			return nil, fmt.Errorf("decode %s: %w", url, err)
		}
		return lr.Data, nil
	}
	return nil, fmt.Errorf("no list endpoint reachable for suffix=%s", suffix)
}

// ListClients returns active clients (the /stat/sta endpoint).
func (u *UniFi) ListClients(ctx context.Context) ([]Client, error) {
	return fetchList[Client](ctx, u, "/stat/sta")
}

// ListDevices returns adopted/known devices (the /stat/device endpoint).
func (u *UniFi) ListDevices(ctx context.Context) ([]Device, error) {
	return fetchList[Device](ctx, u, "/stat/device")
}

// Decider asks tf-daemon /v1/decide. Mirrored from other tf-* Go
// integrations so the wire shape is identical.
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
		controllerURL = flag.String("controller", envOr("UNIFI_URL", "https://unifi.local:8443"), "UniFi controller base URL")
		site          = flag.String("site", envOr("UNIFI_SITE", "default"), "controller site name")
		username      = flag.String("username", envOr("UNIFI_USERNAME", "admin"), "controller user")
		password      = flag.String("password", envOr("UNIFI_PASSWORD", ""), "controller password (env UNIFI_PASSWORD recommended)")
		daemonURL     = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8787"), "tf-daemon base URL")
		outDir        = flag.String("out-dir", envOr("TF_OUT_DIR", ".tf/clients"), "where to drop reconciled actor manifests")
		interval      = flag.Duration("interval", 30*time.Second, "poll interval")
		insecure      = flag.Bool("insecure", false, "skip TLS verification of the controller")
	)
	flag.Parse()

	if *password == "" {
		log.Fatalf("password required (set UNIFI_PASSWORD or pass --password)")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir out-dir: %v", err)
	}

	u, err := NewUniFi(*controllerURL, *site, *username, *password, *insecure)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	dec := NewDecider(*daemonURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := u.Login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}
	log.Printf("tf-unifi-sync started; controller=%s site=%s daemon=%s out=%s",
		*controllerURL, *site, *daemonURL, *outDir)

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		if err := reconcile(ctx, u, dec, *outDir); err != nil {
			log.Printf("reconcile error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
