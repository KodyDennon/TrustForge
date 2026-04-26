// SPDX-License-Identifier: Apache-2.0
//
// Stub cdev driver for non-FreeBSD hosts. Lets the bridge compile and
// be unit-tested on Linux/macOS dev machines, but cannot actually open
// /dev/mac_trustforge.

//go:build !freebsd

package main

import (
	"errors"
	"sync"
)

// stubCdev is a never-yielding driver: ReadEvent blocks until Close.
type stubCdev struct {
	mu     sync.Mutex
	closed bool
	wake   chan struct{}
}

func newCdevDriver() cdevDriver {
	return &stubCdev{wake: make(chan struct{})}
}

func (s *stubCdev) Open(path string) error {
	// On non-FreeBSD hosts the cdev cannot be opened. We accept Open()
	// as a no-op so unit tests can construct a bridge; the kernel
	// module is documented as FreeBSD-only.
	return nil
}

func (s *stubCdev) ReadEvent() ([]byte, error) {
	<-s.wake
	return nil, ErrStopped
}

func (s *stubCdev) WriteVerdict(_ []byte) error {
	return errors.New("cdev write not supported off FreeBSD")
}

func (s *stubCdev) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.wake)
	return nil
}
