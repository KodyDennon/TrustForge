// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"log"
	"reflect"
	"sync"
	"testing"
	"time"
)

// ---------- Policy parser ------------------------------------------

func TestParsePolicyYAML_Minimal(t *testing.T) {
	src := []byte(`
name: example
exec:
  - /bin/cat
  - /etc/passwd
promises:
  - stdio
  - rpath
unveil:
  - path: /etc/passwd
    perm: r
  - path: /tmp
    perm: rwc
`)
	p, err := parsePolicyYAML(src)
	if err != nil {
		t.Fatalf("parsePolicyYAML: %v", err)
	}
	if p.Name != "example" {
		t.Errorf("name: got %q", p.Name)
	}
	if !reflect.DeepEqual(p.Exec, []string{"/bin/cat", "/etc/passwd"}) {
		t.Errorf("exec: got %v", p.Exec)
	}
	if !reflect.DeepEqual(p.Promises, []string{"stdio", "rpath"}) {
		t.Errorf("promises: got %v", p.Promises)
	}
	if len(p.Unveil) != 2 {
		t.Fatalf("unveil: got %d, want 2", len(p.Unveil))
	}
	if p.Unveil[0].Path != "/etc/passwd" || p.Unveil[0].Perm != "r" {
		t.Errorf("unveil[0]: got %+v", p.Unveil[0])
	}
	if p.Unveil[1].Path != "/tmp" || p.Unveil[1].Perm != "rwc" {
		t.Errorf("unveil[1]: got %+v", p.Unveil[1])
	}
	if err := p.validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestParsePolicy_InlineSeq(t *testing.T) {
	src := []byte(`
name: x
exec: [/bin/echo, hi]
promises: [stdio]
`)
	p, err := parsePolicyYAML(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(p.Exec, []string{"/bin/echo", "hi"}) {
		t.Errorf("exec: %v", p.Exec)
	}
}

func TestPolicy_Validate(t *testing.T) {
	cases := []struct {
		name string
		p    Policy
		ok   bool
	}{
		{"missing name", Policy{Exec: []string{"x"}, Promises: []string{"stdio"}}, false},
		{"missing exec", Policy{Name: "x", Promises: []string{"stdio"}}, false},
		{"missing promises", Policy{Name: "x", Exec: []string{"x"}}, false},
		{"unknown promise", Policy{Name: "x", Exec: []string{"x"}, Promises: []string{"foo"}}, false},
		{"bad unveil perm", Policy{Name: "x", Exec: []string{"x"}, Promises: []string{"stdio"},
			Unveil: []UnveilEntry{{Path: "/", Perm: "rxz"}}}, false},
		{"valid", Policy{Name: "x", Exec: []string{"x"}, Promises: []string{"stdio"}}, true},
	}
	for _, tc := range cases {
		err := tc.p.validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: got err=%v want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// ---------- Decision client helpers -------------------------------

func TestIntersectStrings(t *testing.T) {
	got := intersectStrings([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	if !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Errorf("intersect: got %v", got)
	}
	got = intersectStrings([]string{"a", "b"}, nil)
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("nil mask should pass through, got %v", got)
	}
}

func TestIntersectPerm(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"rw", "r", "r"},
		{"rwxc", "rx", "rx"},
		{"r", "", ""},
		{"", "r", ""},
		{"rwc", "rwc", "rwc"},
	}
	for _, tc := range tests {
		got := intersectPerm(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("intersect(%q,%q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// ---------- Supervisor with fakes ---------------------------------

type fakeDecider struct {
	mu       sync.Mutex
	calls    []*DecideRequest
	respond  func(req *DecideRequest) (*DecideResponse, error)
}

func (f *fakeDecider) Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error) {
	f.mu.Lock()
	cp := *req
	f.calls = append(f.calls, &cp)
	f.mu.Unlock()
	if f.respond != nil {
		return f.respond(req)
	}
	return &DecideResponse{Result: 0}, nil
}

type fakeSpawner struct {
	mu       sync.Mutex
	got      *ChildSpec
	exitCode int
	signal   int
	err      error
}

func (f *fakeSpawner) Run(ctx context.Context, spec *ChildSpec) (int, int, error) {
	f.mu.Lock()
	f.got = spec
	f.mu.Unlock()
	return f.exitCode, f.signal, f.err
}

func newTestSupervisor(t *testing.T, dec DecisionClient, sp ChildSpawner, failOpen bool) *Supervisor {
	t.Helper()
	s, err := NewSupervisor(SupervisorConfig{
		DaemonURL: "http://example/v1/decide",
		TimeoutMs: 100,
		FailOpen:  failOpen,
		Logger:    log.New(io.Discard, "", 0),
		Decider:   dec,
		Spawner:   sp,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	return s
}

func TestSupervise_Allow(t *testing.T) {
	dec := &fakeDecider{}
	sp := &fakeSpawner{exitCode: 0}
	s := newTestSupervisor(t, dec, sp, false)
	p := &Policy{
		Name:     "ok",
		Exec:     []string{"/bin/true"},
		Promises: []string{"stdio"},
		Unveil:   []UnveilEntry{{Path: "/etc", Perm: "r"}, {Path: "/tmp", Perm: "rwc"}},
	}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if !out.Allowed {
		t.Errorf("expected Allowed=true")
	}
	if out.UnveilCount != 2 {
		t.Errorf("UnveilCount: got %d", out.UnveilCount)
	}
	// 1 start + 2 unveil + 1 outcome = 4 calls.
	if len(dec.calls) != 4 {
		t.Errorf("decider calls: got %d want 4", len(dec.calls))
	}
	if dec.calls[0].Kind != "pledge_start" {
		t.Errorf("first call kind: got %q", dec.calls[0].Kind)
	}
	if dec.calls[3].Kind != "pledge_outcome" {
		t.Errorf("last call kind: got %q", dec.calls[3].Kind)
	}
}

func TestSupervise_StartDenied(t *testing.T) {
	dec := &fakeDecider{
		respond: func(req *DecideRequest) (*DecideResponse, error) {
			if req.Kind == "pledge_start" {
				return &DecideResponse{Result: 13, Reason: "policy denies"}, nil
			}
			return &DecideResponse{Result: 0}, nil
		},
	}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, false)
	p := &Policy{Name: "x", Exec: []string{"/bin/sh"}, Promises: []string{"stdio"}}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if out.Allowed {
		t.Errorf("expected Allowed=false")
	}
	if out.ExitCode != 126 {
		t.Errorf("ExitCode: got %d want 126", out.ExitCode)
	}
	if sp.got != nil {
		t.Errorf("spawner should not have been called when start is denied")
	}
}

func TestSupervise_UnveilDeniedSkipsEntry(t *testing.T) {
	dec := &fakeDecider{
		respond: func(req *DecideRequest) (*DecideResponse, error) {
			if req.Kind == "pledge_unveil" && req.Path == "/secret" {
				return &DecideResponse{Result: 13, Reason: "no"}, nil
			}
			return &DecideResponse{Result: 0}, nil
		},
	}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, false)
	p := &Policy{
		Name:     "x",
		Exec:     []string{"/bin/cat"},
		Promises: []string{"stdio", "rpath"},
		Unveil: []UnveilEntry{
			{Path: "/etc/passwd", Perm: "r"},
			{Path: "/secret", Perm: "r"},
		},
	}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if !out.Allowed {
		t.Fatalf("Allowed=false")
	}
	if out.UnveilCount != 1 {
		t.Errorf("UnveilCount: got %d want 1", out.UnveilCount)
	}
	// Spawner saw only the surviving unveil.
	if got := sp.got; got != nil && len(got.Unveil) != 1 {
		t.Errorf("spawner unveil: got %v", got.Unveil)
	}
}

func TestSupervise_UnveilPermDowngrade(t *testing.T) {
	dec := &fakeDecider{
		respond: func(req *DecideRequest) (*DecideResponse, error) {
			if req.Kind == "pledge_unveil" {
				// Daemon downgrades rwc -> r.
				return &DecideResponse{Result: 0, Perm: "r"}, nil
			}
			return &DecideResponse{Result: 0}, nil
		},
	}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, false)
	p := &Policy{
		Name: "x", Exec: []string{"/bin/cat"}, Promises: []string{"stdio"},
		Unveil: []UnveilEntry{{Path: "/var", Perm: "rwc"}},
	}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if out.UnveilCount != 1 {
		t.Errorf("UnveilCount: %d", out.UnveilCount)
	}
	if sp.got.Unveil[0].Perm != "r" {
		t.Errorf("unveil perm: got %q want %q", sp.got.Unveil[0].Perm, "r")
	}
}

func TestSupervise_PromiseShrinkByDaemon(t *testing.T) {
	dec := &fakeDecider{
		respond: func(req *DecideRequest) (*DecideResponse, error) {
			if req.Kind == "pledge_start" {
				return &DecideResponse{Result: 0, Promises: []string{"stdio"}}, nil
			}
			return &DecideResponse{Result: 0}, nil
		},
	}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, false)
	p := &Policy{
		Name: "x", Exec: []string{"/bin/cat"},
		Promises: []string{"stdio", "rpath", "wpath"},
	}
	_, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if !reflect.DeepEqual(sp.got.Promises, []string{"stdio"}) {
		t.Errorf("shrunk promises: got %v", sp.got.Promises)
	}
}

func TestSupervise_DaemonErrorFailClosed(t *testing.T) {
	dec := &fakeDecider{
		respond: func(_ *DecideRequest) (*DecideResponse, error) {
			return nil, errors.New("simulated network failure")
		},
	}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, false /* fail-closed */)
	p := &Policy{Name: "x", Exec: []string{"/bin/sh"}, Promises: []string{"stdio"}}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if out.Allowed {
		t.Errorf("fail-closed should deny when daemon errors")
	}
}

func TestSupervise_DaemonErrorFailOpen(t *testing.T) {
	dec := &fakeDecider{
		respond: func(_ *DecideRequest) (*DecideResponse, error) {
			return nil, errors.New("simulated network failure")
		},
	}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, true /* fail-open */)
	p := &Policy{Name: "x", Exec: []string{"/bin/sh"}, Promises: []string{"stdio"}}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if !out.Allowed {
		t.Errorf("fail-open should allow when daemon errors")
	}
}

func TestSupervise_DryRun(t *testing.T) {
	dec := &fakeDecider{}
	sp := &fakeSpawner{exitCode: 99}
	cfg := SupervisorConfig{
		DaemonURL: "http://example/v1/decide",
		TimeoutMs: 50,
		FailOpen:  false,
		DryRun:    true,
		Logger:    log.New(io.Discard, "", 0),
		Decider:   dec,
		Spawner:   sp,
	}
	s, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	p := &Policy{
		Name: "x", Exec: []string{"/bin/true"}, Promises: []string{"stdio"},
		Unveil: []UnveilEntry{{Path: "/etc", Perm: "r"}},
	}
	out, err := s.Supervise(context.Background(), p)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if out.ExitCode != 0 {
		t.Errorf("dry-run exit: got %d", out.ExitCode)
	}
	if sp.got != nil {
		t.Errorf("dry-run should not invoke spawner")
	}
}

func TestSupervise_ContextCancel(t *testing.T) {
	dec := &fakeDecider{}
	sp := &fakeSpawner{}
	s := newTestSupervisor(t, dec, sp, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	p := &Policy{Name: "x", Exec: []string{"/bin/true"}, Promises: []string{"stdio"}}
	_, err := s.Supervise(ctx, p)
	// Either success or canceled; no panic.
	_ = err
}
