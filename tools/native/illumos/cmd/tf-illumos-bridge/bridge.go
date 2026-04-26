// SPDX-License-Identifier: Apache-2.0
//
// bridge.go — illumos DTrace -> TrustForge daemon bridge.
//
// The DTrace probe script (trustforge.d) emits one TFEV line per
// kernel event. This bridge:
//
//   - launches dtrace as a subprocess (or reads from stdin in test
//     mode);
//   - tokenises each TFEV line into a structured Event;
//   - asks tf-daemon /v1/decide for an allow/deny verdict;
//   - logs the verdict (advisory; DTrace cannot block by default);
//   - optionally appends to an audit file for compliance evidence.
//
// Wire format (tab-separated):
//
//   TFEV<TAB>kind=<name><TAB>k=v<TAB>...

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// BridgeConfig is the subset of CLI flags relevant to the bridge.
type BridgeConfig struct {
	DTracePath string
	Script     string
	DTraceArgs []string
	DaemonURL  string
	TimeoutMs  int
	AuditFile  string
	FromStdin  bool
	Logger     *log.Logger
	Verbose    bool
	// Decider is optional; when nil an HTTP one is built.
	Decider DecisionClient
	// EventSource is optional; when nil the bridge spawns dtrace or
	// reads stdin.
	EventSource io.Reader
}

// Event is the parsed in-Go form of a single TFEV line.
type Event struct {
	Kind    string
	TS      uint64
	PID     uint32
	UID     uint32
	Zone    int
	Exec    string
	Path    string
	Family  int
	Addr    string
	Port    int
	Raw     string // original line, for audit
}

// DecideRequest is the JSON shape sent to the TrustForge daemon.
type DecideRequest struct {
	V        int    `json:"v"`
	Platform string `json:"platform"`
	Kind     string `json:"kind"`
	PID      uint32 `json:"pid"`
	UID      uint32 `json:"uid"`
	Zone     int    `json:"zone"`
	Exec     string `json:"exec,omitempty"`
	Path     string `json:"path,omitempty"`
	Family   int    `json:"family,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// DecideResponse is the JSON shape received from the daemon.
type DecideResponse struct {
	Result int32  `json:"result"`
	Reason string `json:"reason,omitempty"`
}

// DecisionClient is implemented by the HTTP client; injectable for
// tests.
type DecisionClient interface {
	Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error)
}

// httpClient talks to /v1/decide over HTTP or unix-socket HTTP.
type httpClient struct {
	url    string
	client *http.Client
}

func newHTTPClient(daemon string, timeoutMs int) (*httpClient, error) {
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
		return &httpClient{
			url:    "http://unix/v1/decide",
			client: &http.Client{Transport: tr, Timeout: timeout},
		}, nil
	}
	return &httpClient{
		url:    daemon,
		client: &http.Client{Timeout: timeout},
	}, nil
}

func (h *httpClient) Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error) {
	if req.V == 0 {
		req.V = 1
	}
	if req.Platform == "" {
		req.Platform = "illumos-dtrace"
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

// Bridge owns the dtrace child process, the line scanner, the
// decision client, and the audit log.
type Bridge struct {
	cfg       BridgeConfig
	logger    *log.Logger
	decider   DecisionClient
	src       io.Reader
	cmd       *exec.Cmd
	auditFile *os.File

	processed atomic.Uint64
	allows    atomic.Uint64
	denies    atomic.Uint64
	parseErr  atomic.Uint64
}

// NewBridge wires together the decider and the event source.
func NewBridge(cfg BridgeConfig) (*Bridge, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "tf-illumos-bridge: ", log.LstdFlags)
	}
	dec := cfg.Decider
	if dec == nil {
		hc, err := newHTTPClient(cfg.DaemonURL, cfg.TimeoutMs)
		if err != nil {
			return nil, err
		}
		dec = hc
	}
	br := &Bridge{cfg: cfg, logger: cfg.Logger, decider: dec, src: cfg.EventSource}
	if cfg.AuditFile != "" {
		f, err := os.OpenFile(cfg.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit file: %w", err)
		}
		br.auditFile = f
	}
	return br, nil
}

// Run is the read/decide loop. It blocks until ctx is cancelled or
// the source EOFs.
func (b *Bridge) Run(ctx context.Context) error {
	defer func() {
		if b.auditFile != nil {
			_ = b.auditFile.Close()
		}
	}()

	src, cleanup, err := b.openSource(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		line := scanner.Text()
		if !strings.HasPrefix(line, "TFEV") {
			continue
		}
		ev, err := ParseEvent(line)
		if err != nil {
			b.parseErr.Add(1)
			if b.cfg.Verbose {
				b.logger.Printf("parse error: %v line=%q", err, line)
			}
			continue
		}
		b.processed.Add(1)
		req := &DecideRequest{
			Kind: ev.Kind, PID: ev.PID, UID: ev.UID, Zone: ev.Zone,
			Exec: ev.Exec, Path: ev.Path, Family: ev.Family,
			Addr: ev.Addr, Port: ev.Port,
		}
		dctx, cancel := context.WithTimeout(ctx, time.Duration(b.cfg.TimeoutMs)*time.Millisecond)
		resp, derr := b.decider.Decide(dctx, req)
		cancel()
		var verdict int32
		var reason string
		if derr != nil {
			verdict = 0 // advisory mode: failure means "allow + log"
			reason = "daemon-error: " + derr.Error()
		} else {
			verdict = resp.Result
			reason = resp.Reason
		}
		if verdict == 0 {
			b.allows.Add(1)
		} else {
			b.denies.Add(1)
		}
		if b.cfg.Verbose {
			b.logger.Printf("kind=%s pid=%d zone=%d path=%q -> verdict=%d reason=%s",
				ev.Kind, ev.PID, ev.Zone, ev.Path, verdict, reason)
		}
		b.writeAudit(ev, verdict, reason)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (b *Bridge) openSource(ctx context.Context) (io.Reader, func(), error) {
	if b.src != nil {
		return b.src, func() {}, nil
	}
	if b.cfg.FromStdin {
		return os.Stdin, func() {}, nil
	}
	args := append([]string{}, b.cfg.DTraceArgs...)
	args = append(args, b.cfg.Script)
	cmd := exec.CommandContext(ctx, b.cfg.DTracePath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start dtrace: %w", err)
	}
	b.cmd = cmd
	cleanup := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
		_ = cmd.Wait()
	}
	return stdout, cleanup, nil
}

func (b *Bridge) writeAudit(ev *Event, verdict int32, reason string) {
	if b.auditFile == nil {
		return
	}
	rec := struct {
		TS      time.Time `json:"ts"`
		Kind    string    `json:"kind"`
		PID     uint32    `json:"pid"`
		UID     uint32    `json:"uid"`
		Zone    int       `json:"zone"`
		Exec    string    `json:"exec,omitempty"`
		Path    string    `json:"path,omitempty"`
		Verdict int32     `json:"verdict"`
		Reason  string    `json:"reason,omitempty"`
	}{
		TS: time.Now().UTC(), Kind: ev.Kind, PID: ev.PID, UID: ev.UID,
		Zone: ev.Zone, Exec: ev.Exec, Path: ev.Path,
		Verdict: verdict, Reason: reason,
	}
	enc := json.NewEncoder(b.auditFile)
	_ = enc.Encode(&rec)
}

// Stats returns counters; primarily for tests.
func (b *Bridge) Stats() (processed, allows, denies, parseErrs uint64) {
	return b.processed.Load(), b.allows.Load(), b.denies.Load(), b.parseErr.Load()
}

// ParseEvent tokenises a single TFEV<TAB>... line.
func ParseEvent(line string) (*Event, error) {
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Split(line, "\t")
	if len(parts) < 2 {
		return nil, errors.New("event has no fields")
	}
	if parts[0] != "TFEV" {
		return nil, fmt.Errorf("expected TFEV prefix, got %q", parts[0])
	}
	ev := &Event{Raw: line}
	for _, p := range parts[1:] {
		k, v, ok := splitKV(p)
		if !ok {
			continue
		}
		switch k {
		case "kind":
			ev.Kind = v
		case "ts":
			n, _ := strconv.ParseUint(v, 10, 64)
			ev.TS = n
		case "pid":
			n, _ := strconv.ParseUint(v, 10, 32)
			ev.PID = uint32(n)
		case "uid":
			n, _ := strconv.ParseUint(v, 10, 32)
			ev.UID = uint32(n)
		case "zone":
			n, _ := strconv.Atoi(v)
			ev.Zone = n
		case "exec":
			ev.Exec = v
		case "path":
			ev.Path = v
		case "family":
			n, _ := strconv.Atoi(v)
			ev.Family = n
		case "addr":
			ev.Addr = v
		case "port":
			n, _ := strconv.Atoi(v)
			ev.Port = n
		}
	}
	if ev.Kind == "" {
		return nil, errors.New("event missing 'kind' field")
	}
	return ev, nil
}

func splitKV(p string) (string, string, bool) {
	idx := strings.Index(p, "=")
	if idx <= 0 {
		return "", "", false
	}
	return p[:idx], p[idx+1:], true
}
