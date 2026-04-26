// SPDX-License-Identifier: Apache-2.0
//
// supervise.go — the core fork+exec loop. The supervisor:
//
//   1. Calls /v1/decide(kind=pledge_start) to check whether the
//      child may run with the requested promises.
//   2. Calls /v1/decide(kind=pledge_unveil) once per UnveilEntry.
//   3. Forks; in the child, applies pledge() then unveil() in the
//      strict order required by OpenBSD (unveil must be called
//      before pledge drops "unveil" itself), then exec()s the binary.
//   4. In the parent, waits for the child and reports outcome.
//
// On non-OpenBSD hosts the actual pledge/unveil syscalls are stubs
// that no-op so the supervisor can be unit-tested everywhere.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// SupervisorConfig captures runtime configuration.
type SupervisorConfig struct {
	DaemonURL string
	TimeoutMs int
	FailOpen  bool
	DryRun    bool
	Logger    *log.Logger
	// Decider is optional; when nil the supervisor builds an HTTP one.
	Decider DecisionClient
	// Spawner is optional; when nil the supervisor uses the real
	// os/exec process (or, on OpenBSD, the pledge/unveil-aware
	// spawner). Tests inject a fake.
	Spawner ChildSpawner
}

// Outcome describes how the supervised child exited.
type Outcome struct {
	ExitCode    int
	Signal      int
	Reason      string
	Allowed     bool   // false if the daemon denied start
	UnveilCount int    // number of unveil calls that survived adjustment
	Promises    []string
}

// Supervisor is the orchestrator. Concurrent Supervise() calls are
// safe — each obtains an independent child process.
type Supervisor struct {
	cfg     SupervisorConfig
	logger  *log.Logger
	decider DecisionClient
	spawner ChildSpawner
	mu      sync.Mutex
}

// NewSupervisor builds a Supervisor, plumbing in defaults for any
// optional fields.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "tf-pledge-supervisor: ", log.LstdFlags)
	}
	dec := cfg.Decider
	if dec == nil {
		d, err := newDecisionClient(cfg.DaemonURL, cfg.TimeoutMs)
		if err != nil {
			return nil, err
		}
		dec = d
	}
	sp := cfg.Spawner
	if sp == nil {
		sp = newDefaultSpawner()
	}
	return &Supervisor{
		cfg:     cfg,
		logger:  cfg.Logger,
		decider: dec,
		spawner: sp,
	}, nil
}

// Supervise runs the policy: start-decision, per-unveil decisions,
// fork+exec, wait, outcome-decision. Supervise returns the final
// outcome regardless of how supervision ended; err is non-nil only
// for *internal* failures (decoder broken, spawner panicked, etc.) —
// daemon denies are reported via Outcome.Allowed=false.
func (s *Supervisor) Supervise(ctx context.Context, p *Policy) (*Outcome, error) {
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}

	// 1. Start decision.
	startReq := &DecideRequest{
		Kind:     "pledge_start",
		Name:     p.Name,
		Argv:     p.Exec,
		Env:      p.Env,
		Promises: p.Promises,
		ExecProm: p.ExecProm,
	}
	startResp, err := s.decideOrFailOpen(ctx, startReq)
	if err != nil {
		return nil, err
	}
	if startResp.Result != 0 {
		s.logger.Printf("pledge_start denied: %s", startResp.Reason)
		return &Outcome{Allowed: false, Reason: startResp.Reason, ExitCode: 126}, nil
	}

	promises := intersectStrings(p.Promises, startResp.Promises)
	execProm := intersectStrings(p.ExecProm, startResp.ExecProm)

	// 2. Unveil decisions.
	finalUnveil := make([]UnveilEntry, 0, len(p.Unveil))
	for _, u := range p.Unveil {
		req := &DecideRequest{
			Kind: "pledge_unveil",
			Name: p.Name,
			Path: u.Path,
			Perm: u.Perm,
		}
		resp, err := s.decideOrFailOpen(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Result != 0 {
			s.logger.Printf("unveil %q denied: %s", u.Path, resp.Reason)
			continue
		}
		perm := u.Perm
		if resp.Perm != "" {
			perm = intersectPerm(u.Perm, resp.Perm)
		}
		if perm == "" {
			s.logger.Printf("unveil %q downgraded to no-access by daemon", u.Path)
			continue
		}
		finalUnveil = append(finalUnveil, UnveilEntry{Path: u.Path, Perm: perm})
	}

	if s.cfg.DryRun {
		s.logger.Printf("dry-run: would exec %v", p.Exec)
		s.logger.Printf("dry-run: pledge %v exec_promises=%v", promises, execProm)
		for _, u := range finalUnveil {
			s.logger.Printf("dry-run: unveil %q %s", u.Path, u.Perm)
		}
		return &Outcome{
			ExitCode:    0,
			Allowed:     true,
			UnveilCount: len(finalUnveil),
			Promises:    promises,
		}, nil
	}

	// 3. Fork + exec via the spawner.
	spec := &ChildSpec{
		Argv:         p.Exec,
		Env:          p.Env,
		Cwd:          p.Cwd,
		Promises:     promises,
		ExecPromises: execProm,
		Unveil:       finalUnveil,
	}
	exitCode, sig, err := s.spawner.Run(ctx, spec)
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, fmt.Errorf("spawner run: %w", err)
	}

	// 4. Outcome decision (best-effort, fire-and-forget).
	outReq := &DecideRequest{
		Kind:     "pledge_outcome",
		Name:     p.Name,
		ExitCode: exitCode,
		Signal:   sig,
	}
	if _, ferr := s.decideOrFailOpen(ctx, outReq); ferr != nil {
		s.logger.Printf("outcome notify failed: %v", ferr)
	}

	return &Outcome{
		ExitCode:    exitCode,
		Signal:      sig,
		Allowed:     true,
		UnveilCount: len(finalUnveil),
		Promises:    promises,
	}, nil
}

// decideOrFailOpen wraps a Decide call so callers don't have to
// repeat the FailOpen logic.
func (s *Supervisor) decideOrFailOpen(ctx context.Context, req *DecideRequest) (*DecideResponse, error) {
	resp, err := s.decider.Decide(ctx, req)
	if err == nil {
		return resp, nil
	}
	if s.cfg.FailOpen {
		s.logger.Printf("daemon error %v; FailOpen=true, allowing %s", err, req.Kind)
		return &DecideResponse{Result: 0, Reason: "fail-open"}, nil
	}
	s.logger.Printf("daemon error %v; FailOpen=false, denying %s", err, req.Kind)
	return &DecideResponse{Result: 13, Reason: "fail-closed: " + err.Error()}, nil
}

// ChildSpec is the hand-off from supervisor to spawner.
type ChildSpec struct {
	Argv         []string
	Env          []string
	Cwd          string
	Promises     []string
	ExecPromises []string
	Unveil       []UnveilEntry
}

// ChildSpawner is implemented per-platform. On OpenBSD it applies
// pledge() and unveil() in the child before exec; on other hosts it
// merely exec()s (warning loudly).
type ChildSpawner interface {
	// Run starts the child according to spec, blocks until it
	// exits or ctx is cancelled, and returns (exitCode, signal,
	// error). signal is 0 if the child exited normally.
	Run(ctx context.Context, spec *ChildSpec) (int, int, error)
}

// genericSpawner runs the child via os/exec without applying any
// pledge/unveil syscalls. Used on non-OpenBSD hosts and as a base
// for the OpenBSD spawner.
type genericSpawner struct {
	applyPledgeUnveil func(promises, execProm []string, unveil []UnveilEntry) error
}

func newGenericSpawner(apply func(promises, execProm []string, unveil []UnveilEntry) error) ChildSpawner {
	return &genericSpawner{applyPledgeUnveil: apply}
}

func (g *genericSpawner) Run(ctx context.Context, spec *ChildSpec) (int, int, error) {
	if len(spec.Argv) == 0 {
		return 1, 0, errors.New("empty argv")
	}
	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	cmd.Env = spec.Env
	if spec.Cwd != "" {
		cmd.Dir = spec.Cwd
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// On OpenBSD the SysProcAttr would carry custom syscalls; here
	// we rely on a re-exec stub that the real OpenBSD spawner
	// implements. For the generic path we just run the binary.
	if g.applyPledgeUnveil != nil {
		// In a real fork-then-pledge implementation we'd run this
		// in the child after fork() but before execve(). With
		// os/exec that lifecycle is inverted; the OpenBSD-specific
		// spawner overrides Run() entirely.
		_ = g.applyPledgeUnveil
	}

	err := cmd.Run()
	exit := 0
	sig := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			ws, ok := ee.Sys().(syscall.WaitStatus)
			if ok {
				if ws.Signaled() {
					sig = int(ws.Signal())
					exit = 128 + sig
				} else {
					exit = ws.ExitStatus()
				}
			} else {
				exit = ee.ExitCode()
			}
			err = nil
		} else {
			exit = 127
		}
	}
	return exit, sig, err
}
