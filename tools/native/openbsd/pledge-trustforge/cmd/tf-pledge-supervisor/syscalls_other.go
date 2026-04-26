// SPDX-License-Identifier: Apache-2.0
//
// Stub spawner for non-OpenBSD hosts. The pledge/unveil syscalls do
// not exist; the child runs without restriction. This is so the
// supervisor logic can be unit-tested on macOS/Linux developer hosts.
// Operators must not use this spawner in production.

//go:build !openbsd

package main

import "os"

func newDefaultSpawner() ChildSpawner {
	return newGenericSpawner(func(_, _ []string, _ []UnveilEntry) error {
		// no-op on non-OpenBSD
		return nil
	})
}

// applyOpenBSDChild is a no-op off OpenBSD.
func applyOpenBSDChild() error {
	_ = os.Getenv
	return nil
}
