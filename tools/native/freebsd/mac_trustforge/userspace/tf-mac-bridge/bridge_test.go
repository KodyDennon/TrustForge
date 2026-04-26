// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ---------- Wire format round-trip ---------------------------------

// makeRawEvent builds a wire-format tf_event byte slice for tests.
func makeRawEvent(cookie uint64, kind uint32, path string) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, tfEventSize))
	write := func(v any) {
		switch x := v.(type) {
		case uint32:
			b := []byte{byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24)}
			buf.Write(b)
		case uint64:
			b := make([]byte, 8)
			for i := 0; i < 8; i++ {
				b[i] = byte(x >> (8 * i))
			}
			buf.Write(b)
		}
	}
	write(tfEventMagic)
	write(uint32(1))                  // version
	write(cookie)                     // cookie
	write(kind)                       // kind
	write(uint32(4242))               // pid
	write(uint32(1000))               // uid
	write(uint32(1000))               // gid
	write(uint32(0x42))               // mask
	write(uint32(0))                  // target_pid
	write(uint32(0))                  // target_sig
	write(uint32(len(path)))          // path_len
	pathBytes := make([]byte, tfMaxPath)
	copy(pathBytes, []byte(path))
	buf.Write(pathBytes)
	return buf.Bytes()
}

func TestDecodeEvent_RoundTrip(t *testing.T) {
	raw := makeRawEvent(0xCAFEBABE, kindVnodeOpen, "/etc/passwd")
	if len(raw) != tfEventSize {
		t.Fatalf("event size mismatch: got %d, want %d", len(raw), tfEventSize)
	}
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if ev.Cookie != 0xCAFEBABE {
		t.Errorf("cookie: got %x, want %x", ev.Cookie, uint64(0xCAFEBABE))
	}
	if ev.Kind != kindVnodeOpen {
		t.Errorf("kind: got %d, want %d", ev.Kind, kindVnodeOpen)
	}
	if ev.Path != "/etc/passwd" {
		t.Errorf("path: got %q, want %q", ev.Path, "/etc/passwd")
	}
	if ev.PID != 4242 {
		t.Errorf("pid: got %d, want 4242", ev.PID)
	}
}

func TestDecodeEvent_RejectsBadMagic(t *testing.T) {
	raw := makeRawEvent(1, kindVnodeOpen, "/x")
	raw[0] = 0xFF
	if _, err := DecodeEvent(raw); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestDecodeEvent_RejectsShort(t *testing.T) {
	if _, err := DecodeEvent([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short event")
	}
}

func TestEncodeVerdict_Size(t *testing.T) {
	out := EncodeVerdict(TFVerdict{Cookie: 7, Result: -13})
	if len(out) != tfVerdictSize {
		t.Fatalf("verdict size: got %d, want %d", len(out), tfVerdictSize)
	}
	// magic 0x54465644 little-endian -> 0x44 0x56 0x46 0x54 -> 'D' 'V' 'F' 'T'
	if out[0] != 'D' || out[1] != 'V' || out[2] != 'F' || out[3] != 'T' {
		t.Errorf("verdict magic bytes: got %v", out[:4])
	}
}

func TestKindName(t *testing.T) {
	tests := map[uint32]string{
		kindVnodeOpen:     "vnode_open",
		kindVnodeExec:     "vnode_exec",
		kindSocketConnect: "socket_connect",
		kindProcSignal:    "proc_signal",
	}
	for k, want := range tests {
		if got := kindName(k); got != want {
			t.Errorf("kindName(%d): got %q, want %q", k, got, want)
		}
	}
	if got := kindName(99); got == "" {
		t.Errorf("kindName(unknown) should not be empty")
	}
}

// ---------- Fake cdev driver and end-to-end loop -------------------

type fakeCdev struct {
	mu        sync.Mutex
	events    [][]byte
	verdicts  [][]byte
	in        chan []byte
	stopped   bool
	stopMu    sync.Mutex
	verdictCh chan []byte
}

func newFakeCdev(events [][]byte) *fakeCdev {
	in := make(chan []byte, len(events))
	for _, e := range events {
		in <- e
	}
	return &fakeCdev{
		events:    events,
		in:        in,
		verdictCh: make(chan []byte, len(events)),
	}
}

func (f *fakeCdev) Open(_ string) error { return nil }

func (f *fakeCdev) ReadEvent() ([]byte, error) {
	ev, ok := <-f.in
	if !ok {
		return nil, ErrStopped
	}
	return ev, nil
}

func (f *fakeCdev) WriteVerdict(b []byte) error {
	out := make([]byte, len(b))
	copy(out, b)
	f.mu.Lock()
	f.verdicts = append(f.verdicts, out)
	f.mu.Unlock()
	f.verdictCh <- out
	return nil
}

func (f *fakeCdev) Close() error {
	f.stopMu.Lock()
	defer f.stopMu.Unlock()
	if f.stopped {
		return nil
	}
	f.stopped = true
	close(f.in)
	return nil
}

// fakeDaemon serves /v1/decide returning a configurable verdict.
func fakeDaemon(t *testing.T, verdict int32, sawCh chan<- decideRequest) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decide", func(w http.ResponseWriter, r *http.Request) {
		var req decideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if sawCh != nil {
			sawCh <- req
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decideResponse{Result: verdict})
	})
	return httptest.NewServer(mux)
}

func TestBridgeEndToEnd_AllowVerdict(t *testing.T) {
	saw := make(chan decideRequest, 4)
	srv := fakeDaemon(t, 0, saw)
	defer srv.Close()

	decider, err := newDecider(srv.URL+"/v1/decide", 500, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newDecider: %v", err)
	}
	cdev := newFakeCdev([][]byte{
		makeRawEvent(1, kindVnodeOpen, "/bin/ls"),
		makeRawEvent(2, kindVnodeExec, "/bin/sh"),
	})
	br := &Bridge{
		device:   "fake",
		failOpen: true,
		logger:   log.New(io.Discard, "", 0),
		decision: decider,
		timeout:  500 * time.Millisecond,
		driver:   cdev,
	}
	// Run in a goroutine, then close the cdev to stop.
	done := make(chan error, 1)
	go func() { done <- br.Run() }()
	// Wait for both verdicts.
	for i := 0; i < 2; i++ {
		select {
		case <-cdev.verdictCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for verdict %d", i+1)
		}
	}
	cdev.Close()
	if err := <-done; err != nil {
		t.Fatalf("bridge run: %v", err)
	}
	processed, allows, denies := br.Stats()
	if processed != 2 {
		t.Errorf("processed: got %d want 2", processed)
	}
	if allows != 2 {
		t.Errorf("allows: got %d want 2", allows)
	}
	if denies != 0 {
		t.Errorf("denies: got %d want 0", denies)
	}
	// Confirm daemon saw both events with expected fields.
	close(saw)
	count := 0
	for r := range saw {
		count++
		if r.Platform != "freebsd-mac" {
			t.Errorf("platform: got %q", r.Platform)
		}
	}
	if count != 2 {
		t.Errorf("daemon saw %d requests, want 2", count)
	}
}

func TestBridgeEndToEnd_DenyVerdict(t *testing.T) {
	srv := fakeDaemon(t, 13 /* EACCES */, nil)
	defer srv.Close()
	decider, err := newDecider(srv.URL+"/v1/decide", 500, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newDecider: %v", err)
	}
	cdev := newFakeCdev([][]byte{
		makeRawEvent(99, kindSocketConnect, "ip4:10.0.0.1:443"),
	})
	br := &Bridge{
		failOpen: true,
		logger:   log.New(io.Discard, "", 0),
		decision: decider,
		timeout:  500 * time.Millisecond,
		driver:   cdev,
	}
	done := make(chan error, 1)
	go func() { done <- br.Run() }()
	select {
	case <-cdev.verdictCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for verdict")
	}
	cdev.Close()
	<-done
	_, allows, denies := br.Stats()
	if allows != 0 || denies != 1 {
		t.Errorf("allows=%d denies=%d, want 0/1", allows, denies)
	}
}

func TestBridgeEndToEnd_DaemonDownFailOpen(t *testing.T) {
	// Point at an unreachable URL and ensure fail-open allows.
	decider, err := newDecider("http://127.0.0.1:1/v1/decide", 50, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newDecider: %v", err)
	}
	cdev := newFakeCdev([][]byte{
		makeRawEvent(7, kindVnodeOpen, "/etc/hosts"),
	})
	br := &Bridge{
		failOpen: true,
		logger:   log.New(io.Discard, "", 0),
		decision: decider,
		timeout:  50 * time.Millisecond,
		driver:   cdev,
	}
	done := make(chan error, 1)
	go func() { done <- br.Run() }()
	select {
	case <-cdev.verdictCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for fail-open verdict")
	}
	cdev.Close()
	<-done
	_, allows, denies := br.Stats()
	if allows != 1 || denies != 0 {
		t.Errorf("fail-open should allow: allows=%d denies=%d", allows, denies)
	}
}

func TestBridgeEndToEnd_DaemonDownFailClosed(t *testing.T) {
	decider, err := newDecider("http://127.0.0.1:1/v1/decide", 50, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newDecider: %v", err)
	}
	cdev := newFakeCdev([][]byte{
		makeRawEvent(7, kindVnodeOpen, "/etc/hosts"),
	})
	br := &Bridge{
		failOpen: false,
		logger:   log.New(io.Discard, "", 0),
		decision: decider,
		timeout:  50 * time.Millisecond,
		driver:   cdev,
	}
	done := make(chan error, 1)
	go func() { done <- br.Run() }()
	select {
	case <-cdev.verdictCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for fail-closed verdict")
	}
	cdev.Close()
	<-done
	_, allows, denies := br.Stats()
	if allows != 0 || denies != 1 {
		t.Errorf("fail-closed should deny: allows=%d denies=%d", allows, denies)
	}
}
