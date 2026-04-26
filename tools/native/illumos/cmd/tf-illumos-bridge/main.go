// SPDX-License-Identifier: Apache-2.0
//
// tf-illumos-bridge — DTrace event reader / TrustForge decision
// dispatcher for illumos.
//
// Spawns `dtrace -qs trustforge.d` as a subprocess, parses the
// stream of TFEV lines, and forwards each event to the local
// TrustForge daemon (/v1/decide). The daemon's verdict is logged
// (and optionally written to a per-zone audit file) but is NOT
// enforced — see README.md. illumos DTrace can observe but not
// block by default.
//
// Build constraints: this binary compiles on any host. The dtrace
// binary itself is illumos-only; on other hosts the --exec flag
// can point at a fake feeder for testing.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	var (
		dtraceBin  = flag.String("dtrace", "/usr/sbin/dtrace", "Path to the dtrace binary")
		script     = flag.String("script", "/usr/lib/trustforge/trustforge.d", "Path to trustforge.d")
		dtraceArgs = flag.String("dtrace-args", "-qs", "Extra args passed to dtrace")
		daemonURL  = flag.String("daemon", "http://127.0.0.1:8787/v1/decide", "TrustForge /v1/decide endpoint")
		timeoutMs  = flag.Int("timeout", 200, "Per-decision timeout (ms)")
		audit      = flag.String("audit", "", "If set, append decisions to this file (advisory)")
		fromStdin  = flag.Bool("stdin", false, "Read events from stdin instead of dtrace")
		verbose    = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "tf-illumos-bridge: ", log.LstdFlags|log.Lmicroseconds)

	cfg := BridgeConfig{
		DTracePath: *dtraceBin,
		Script:     *script,
		DTraceArgs: strings.Fields(*dtraceArgs),
		DaemonURL:  *daemonURL,
		TimeoutMs:  *timeoutMs,
		AuditFile:  *audit,
		FromStdin:  *fromStdin,
		Logger:     logger,
		Verbose:    *verbose,
	}

	br, err := NewBridge(cfg)
	if err != nil {
		logger.Fatalf("init: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigc
		logger.Printf("signal %v, shutting down", s)
		cancel()
	}()

	if err := br.Run(ctx); err != nil {
		logger.Fatalf("run: %v", err)
	}
	fmt.Fprintln(os.Stderr, "tf-illumos-bridge: stopped")
}
