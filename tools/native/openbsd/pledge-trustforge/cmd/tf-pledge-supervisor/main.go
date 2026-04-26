// SPDX-License-Identifier: Apache-2.0
//
// tf-pledge-supervisor — TrustForge OpenBSD supervisor.
//
// OpenBSD does not expose an LSM-style kernel framework. The closest
// idiomatic equivalent is the pledge(2) / unveil(2) pair, which let a
// process voluntarily restrict itself to a subset of syscalls and
// filesystem paths. This program is a TrustForge-aware supervisor
// that:
//
//   1. Reads a YAML policy describing the child to run, the pledge
//      promises it should request, and the unveil paths it needs.
//   2. Asks the local TrustForge daemon (/v1/decide) whether the
//      child is allowed to start with the requested capabilities and
//      whether each unveil entry is permitted.
//   3. fork+exec()s the child. The child re-execs itself through a
//      thin re-exec helper that invokes pledge() / unveil() as the
//      supervisor instructs and only then execve()s the real binary.
//   4. Watches the child for exit / signal / SIGCHLD and reports a
//      structured outcome back to the daemon.
//
// On non-OpenBSD hosts the actual pledge/unveil syscalls are stubs
// (build-tagged in syscalls_other.go) so the binary compiles
// everywhere; only the supervisor logic is exercised in tests.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var (
		policyPath = flag.String("policy", "", "Path to YAML policy file")
		daemonURL  = flag.String("daemon", "http://127.0.0.1:8787/v1/decide", "TrustForge /v1/decide endpoint")
		timeoutMs  = flag.Int("timeout", 500, "Per-decision timeout in milliseconds")
		failOpen   = flag.Bool("fail-open", false, "On daemon error, allow (true) or deny (false). Default deny — stricter than the LSM port.")
		dryRun     = flag.Bool("dry-run", false, "Print decisions and exit without exec()")
		verbose    = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "tf-pledge-supervisor: ", log.LstdFlags|log.Lmicroseconds)

	if *policyPath == "" && flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: tf-pledge-supervisor --policy=<file> [-- <argv0> [args...]]")
		os.Exit(2)
	}

	policy, err := loadPolicy(*policyPath, flag.Args())
	if err != nil {
		logger.Fatalf("load policy: %v", err)
	}
	if *verbose {
		logger.Printf("loaded policy: name=%q exec=%v promises=%v unveil=%d",
			policy.Name, policy.Exec, policy.Promises, len(policy.Unveil))
	}

	cfg := SupervisorConfig{
		DaemonURL: *daemonURL,
		TimeoutMs: *timeoutMs,
		FailOpen:  *failOpen,
		DryRun:    *dryRun,
		Logger:    logger,
	}

	sup, err := NewSupervisor(cfg)
	if err != nil {
		logger.Fatalf("supervisor init: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigc
		logger.Printf("signal %v received, terminating child", s)
		cancel()
	}()

	outcome, err := sup.Supervise(ctx, policy)
	if err != nil {
		logger.Fatalf("supervise: %v", err)
	}
	if *verbose {
		logger.Printf("outcome: %+v", outcome)
	}
	os.Exit(outcome.ExitCode)
}
