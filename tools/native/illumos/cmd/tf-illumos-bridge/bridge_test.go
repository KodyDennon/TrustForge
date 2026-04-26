// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- ParseEvent ---------------------------------------------

func TestParseEvent_OpenSyscall(t *testing.T) {
	line := "TFEV\tkind=vnode_open\tts=12345\tpid=4242\tuid=1000\tzone=0\texec=cat\tpath=/etc/passwd"
	ev, err := ParseEvent(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Kind != "vnode_open" {
		t.Errorf("kind: got %q", ev.Kind)
	}
	if ev.PID != 4242 {
		t.Errorf("pid: got %d", ev.PID)
	}
	if ev.UID != 1000 {
		t.Errorf("uid: got %d", ev.UID)
	}
	if ev.Zone != 0 {
		t.Errorf("zone: got %d", ev.Zone)
	}
	if ev.Path != "/etc/passwd" {
		t.Errorf("path: got %q", ev.Path)
	}
	if ev.Exec != "cat" {
		t.Errorf("exec: got %q", ev.Exec)
	}
}

func TestParseEvent_Connect(t *testing.T) {
	line := "TFEV\tkind=socket_connect\tts=999\tpid=10\tuid=0\tzone=2\texec=curl\tfamily=2\taddr=10.0.0.1\tport=443"
	ev, err := ParseEvent(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Family != 2 || ev.Addr != "10.0.0.1" || ev.Port != 443 {
		t.Errorf("connect fields: got family=%d addr=%q port=%d", ev.Family, ev.Addr, ev.Port)
	}
	if ev.Zone != 2 {
		t.Errorf("zone: got %d", ev.Zone)
	}
}

func TestParseEvent_Exec(t *testing.T) {
	line := "TFEV\tkind=vnode_exec\tts=1\tpid=1\tuid=0\tzone=0\texec=sh\tpath=/bin/ls"
	ev, err := ParseEvent(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Kind != "vnode_exec" || ev.Path != "/bin/ls" {
		t.Errorf("exec fields: %+v", ev)
	}
}

func TestParseEvent_RejectsNonTFEV(t *testing.T) {
	if _, err := ParseEvent("HELLO"); err == nil {
		t.Fatal("expected error for non-TFEV line")
	}
	if _, err := ParseEvent(""); err == nil {
		t.Fatal("expected error for empty line")
	}
}

func TestParseEvent_RequiresKind(t *testing.T) {
	line := "TFEV\tts=1\tpid=1"
	if _, err := ParseEvent(line); err == nil {
		t.Fatal("expected error when kind missing")
	}
}

func TestParseEvent_IgnoresUnknownKeys(t *testing.T) {
	line := "TFEV\tkind=vnode_open\tnewkey=v\tpid=7\tts=0\tuid=0\tzone=0\texec=x"
	ev, err := ParseEvent(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.PID != 7 {
		t.Errorf("pid: got %d", ev.PID)
	}
}

// ---------- End-to-end with a fake event source --------------------

type fakeDecider struct {
	mu      sync.Mutex
	calls   []*DecideRequest
	respond func(*DecideRequest) (*DecideResponse, error)
}

func (f *fakeDecider) Decide(_ context.Context, req *DecideRequest) (*DecideResponse, error) {
	f.mu.Lock()
	cp := *req
	f.calls = append(f.calls, &cp)
	f.mu.Unlock()
	if f.respond != nil {
		return f.respond(req)
	}
	return &DecideResponse{Result: 0}, nil
}

func TestBridge_EndToEnd(t *testing.T) {
	src := strings.NewReader(strings.Join([]string{
		"TFINIT\tversion=1\tprobes=open,exec,connect",
		"TFEV\tkind=vnode_open\tts=1\tpid=2\tuid=3\tzone=0\texec=cat\tpath=/etc/hosts",
		"junk line ignored",
		"TFEV\tkind=vnode_exec\tts=2\tpid=3\tuid=3\tzone=0\texec=sh\tpath=/bin/ls",
		"TFEV\tkind=socket_connect\tts=3\tpid=4\tuid=0\tzone=1\texec=curl\tfamily=2\taddr=10.0.0.1\tport=443",
	}, "\n"))

	dec := &fakeDecider{
		respond: func(req *DecideRequest) (*DecideResponse, error) {
			if req.Kind == "socket_connect" && req.Port == 443 {
				return &DecideResponse{Result: 13, Reason: "deny"}, nil
			}
			return &DecideResponse{Result: 0}, nil
		},
	}

	br, err := NewBridge(BridgeConfig{
		DaemonURL:   "http://example/v1/decide",
		TimeoutMs:   100,
		Logger:      log.New(io.Discard, "", 0),
		Decider:     dec,
		EventSource: src,
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	if err := br.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	processed, allows, denies, parseErrs := br.Stats()
	if processed != 3 {
		t.Errorf("processed: got %d want 3", processed)
	}
	if allows != 2 || denies != 1 {
		t.Errorf("allows/denies: got %d/%d want 2/1", allows, denies)
	}
	if parseErrs != 0 {
		t.Errorf("parseErrs: got %d", parseErrs)
	}
	if got := len(dec.calls); got != 3 {
		t.Errorf("decider calls: %d", got)
	}
	// Verify zone ID propagated for the connect.
	for _, c := range dec.calls {
		if c.Kind == "socket_connect" && c.Zone != 1 {
			t.Errorf("connect zone: got %d", c.Zone)
		}
	}
}

func TestBridge_DaemonErrorBecomesAdvisoryAllow(t *testing.T) {
	src := strings.NewReader("TFEV\tkind=vnode_open\tts=1\tpid=2\tuid=0\tzone=0\texec=x\tpath=/y\n")
	dec := &fakeDecider{
		respond: func(_ *DecideRequest) (*DecideResponse, error) {
			return nil, errors.New("network down")
		},
	}
	br, err := NewBridge(BridgeConfig{
		DaemonURL: "http://example", TimeoutMs: 50,
		Logger:      log.New(io.Discard, "", 0),
		Decider:     dec,
		EventSource: src,
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	if err := br.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_, allows, denies, _ := br.Stats()
	if allows != 1 || denies != 0 {
		t.Errorf("advisory mode should count as allow on daemon error: got %d/%d", allows, denies)
	}
}

func TestBridge_AuditFile(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	src := strings.NewReader("TFEV\tkind=vnode_exec\tts=1\tpid=10\tuid=0\tzone=2\texec=sh\tpath=/bin/sh\n")
	dec := &fakeDecider{}
	br, err := NewBridge(BridgeConfig{
		DaemonURL: "http://example", TimeoutMs: 50,
		Logger:      log.New(io.Discard, "", 0),
		Decider:     dec,
		EventSource: src,
		AuditFile:   auditPath,
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	if err := br.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(data), `"kind":"vnode_exec"`) {
		t.Errorf("audit content missing kind: %s", string(data))
	}
	var rec map[string]any
	if err := json.NewDecoder(strings.NewReader(string(data))).Decode(&rec); err != nil {
		t.Errorf("audit not JSON: %v", err)
	}
	if rec["zone"].(float64) != 2 {
		t.Errorf("audit zone: got %v", rec["zone"])
	}
}

func TestBridge_HTTPDecider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req DecideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Platform != "illumos-dtrace" {
			http.Error(w, "wrong platform", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Result: 0})
	}))
	defer srv.Close()

	hc, err := newHTTPClient(srv.URL+"/v1/decide", 500)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	resp, err := hc.Decide(context.Background(), &DecideRequest{Kind: "vnode_open", PID: 1})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if resp.Result != 0 {
		t.Errorf("result: got %d", resp.Result)
	}
}

func TestBridge_ContextCancelStops(t *testing.T) {
	// A reader that blocks forever to simulate dtrace.
	pr, _ := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	br, err := NewBridge(BridgeConfig{
		DaemonURL:   "http://example",
		TimeoutMs:   50,
		Logger:      log.New(io.Discard, "", 0),
		Decider:     &fakeDecider{},
		EventSource: pr,
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- br.Run(ctx) }()
	cancel()
	_ = pr.Close() // unblock the scanner
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}
