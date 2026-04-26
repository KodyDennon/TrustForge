// SPDX-License-Identifier: Apache-2.0
//
// tf-mac-bridge — userspace companion for the TrustForge FreeBSD MAC
// policy module.
//
// Opens /dev/mac_trustforge, reads tf_event records, asks the local
// TrustForge daemon (via its /v1/decide HTTP endpoint or its Unix
// socket) for a verdict, and writes a tf_verdict back. Failure modes
// fail-open by default to match the kernel-side policy.
//
// The kernel module exposes the cdev only on FreeBSD; this binary
// builds on any host but only the FreeBSD build path opens the device.
// On other hosts a no-op driver is provided so unit tests can run on
// the developer machine.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const (
	defaultDevice  = "/dev/mac_trustforge"
	defaultDaemon  = "http://127.0.0.1:8787/v1/decide"
	defaultTimeout = 100 // milliseconds
)

func main() {
	var (
		dev       = flag.String("device", defaultDevice, "MAC framework cdev to read from")
		daemon    = flag.String("daemon", defaultDaemon, "TrustForge daemon /v1/decide URL or unix path")
		timeoutMs = flag.Int("timeout", defaultTimeout, "Decision timeout in milliseconds")
		failOpen  = flag.Bool("fail-open", true, "On daemon error, allow (true) or deny (false)")
		verbose   = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "tf-mac-bridge: ", log.LstdFlags|log.Lmicroseconds)
	if *verbose {
		logger.Printf("starting device=%s daemon=%s timeout=%dms fail_open=%v",
			*dev, *daemon, *timeoutMs, *failOpen)
	}

	br, err := NewBridge(*dev, *daemon, *timeoutMs, *failOpen, logger)
	if err != nil {
		logger.Fatalf("bridge init failed: %v", err)
	}
	defer br.Close()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s := <-sigc
		logger.Printf("signal %v received, shutting down", s)
		br.Stop()
	}()

	if err := br.Run(); err != nil {
		logger.Fatalf("bridge exited with error: %v", err)
	}
	fmt.Fprintln(os.Stderr, "tf-mac-bridge: stopped cleanly")
}
