// SPDX-License-Identifier: Apache-2.0
//
// OpenBSD-specific spawner. Uses a re-exec helper pattern: this
// supervisor re-execs itself with TF_PLEDGE_CHILD=1 set, the re-execed
// instance applies unveil(2) and pledge(2) and then execve(2)s the
// real target.
//
// Why re-exec instead of fork-then-pledge directly: Go's runtime
// starts threads that can be incompatible with the most restrictive
// promise sets (it needs `proc`, `tmppath`, etc. to manage those
// threads). The single-threaded re-exec child applies the promises
// just before exec(2) and never returns, so the runtime never needs
// the dropped promises.
//
// We invoke pledge(2) and unveil(2) via syscall.Syscall directly
// because the Go stdlib `syscall` package does not export named
// wrappers for them on all OpenBSD architectures. The syscall numbers
// SYS_PLEDGE=108 / SYS_UNVEIL=114 are stable across the supported
// architectures (amd64, arm64, riscv64) per
// `sys/sys/syscall.h`.

//go:build openbsd

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// OpenBSD pledge / unveil syscall numbers.
const (
	sysPledge = 108
	sysUnveil = 114
)

// newDefaultSpawner is called by NewSupervisor on OpenBSD.
func newDefaultSpawner() ChildSpawner {
	return &openbsdSpawner{}
}

type openbsdSpawner struct{}

func (o *openbsdSpawner) Run(ctx context.Context, spec *ChildSpec) (int, int, error) {
	self, err := os.Executable()
	if err != nil {
		return 1, 0, fmt.Errorf("os.Executable: %w", err)
	}
	cmd := exec.CommandContext(ctx, self, append([]string{"--child"}, spec.Argv...)...)
	cmd.Env = append([]string{
		"TF_PLEDGE_CHILD=1",
		"TF_PLEDGE_PROMISES=" + strings.Join(spec.Promises, " "),
		"TF_PLEDGE_EXEC_PROMISES=" + strings.Join(spec.ExecPromises, " "),
		"TF_PLEDGE_UNVEIL=" + encodeUnveil(spec.Unveil),
	}, spec.Env...)
	if spec.Cwd != "" {
		cmd.Dir = spec.Cwd
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Run()
	exit, sig := 0, 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
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

func encodeUnveil(u []UnveilEntry) string {
	parts := make([]string, 0, len(u))
	for _, e := range u {
		parts = append(parts, e.Path+":"+e.Perm)
	}
	return strings.Join(parts, "|")
}

// applyOpenBSDChild is invoked from main.go on the re-exec leg.
// It applies unveil() then pledge(), in that order, before returning
// to the caller (which then exec()s the target binary).
func applyOpenBSDChild() error {
	if os.Getenv("TF_PLEDGE_CHILD") != "1" {
		return errors.New("not in pledge child")
	}
	unveilSpec := os.Getenv("TF_PLEDGE_UNVEIL")
	if unveilSpec != "" {
		for _, entry := range strings.Split(unveilSpec, "|") {
			i := strings.LastIndex(entry, ":")
			if i < 0 {
				continue
			}
			path, perm := entry[:i], entry[i+1:]
			if err := unveil(path, perm); err != nil {
				return fmt.Errorf("unveil(%q,%q): %w", path, perm, err)
			}
		}
		// Lock unveil so further unveils are denied.
		if err := unveil("", ""); err != nil {
			return fmt.Errorf("unveil-block: %w", err)
		}
	}
	promises := os.Getenv("TF_PLEDGE_PROMISES")
	execProm := os.Getenv("TF_PLEDGE_EXEC_PROMISES")
	if promises != "" || execProm != "" {
		if err := pledge(promises, execProm); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}
	}
	return nil
}

// unveil wraps the OpenBSD unveil(2) syscall. Passing path="" perm=""
// means "lock unveil" — no further unveils permitted.
func unveil(path, perm string) error {
	var p1, p2 unsafe.Pointer
	if path != "" {
		pb, err := syscall.BytePtrFromString(path)
		if err != nil {
			return err
		}
		p1 = unsafe.Pointer(pb)
	}
	if perm != "" {
		pb, err := syscall.BytePtrFromString(perm)
		if err != nil {
			return err
		}
		p2 = unsafe.Pointer(pb)
	}
	_, _, errno := syscall.Syscall(sysUnveil,
		uintptr(p1), uintptr(p2), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// pledge wraps the OpenBSD pledge(2) syscall. Passing an empty string
// for either argument leaves the corresponding promise set unchanged
// (NULL semantics in pledge(2)).
func pledge(promises, execPromises string) error {
	var p1, p2 unsafe.Pointer
	if promises != "" {
		pb, err := syscall.BytePtrFromString(promises)
		if err != nil {
			return err
		}
		p1 = unsafe.Pointer(pb)
	}
	if execPromises != "" {
		pb, err := syscall.BytePtrFromString(execPromises)
		if err != nil {
			return err
		}
		p2 = unsafe.Pointer(pb)
	}
	_, _, errno := syscall.Syscall(sysPledge,
		uintptr(p1), uintptr(p2), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
