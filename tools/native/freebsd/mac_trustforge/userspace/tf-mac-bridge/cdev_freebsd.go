// SPDX-License-Identifier: Apache-2.0

//go:build freebsd

package main

import (
	"errors"
	"io"
	"os"
	"sync"
)

// freebsdCdev opens /dev/mac_trustforge for blocking read/write of
// fixed-size tf_event / tf_verdict records.
type freebsdCdev struct {
	mu sync.Mutex
	f  *os.File
}

func newCdevDriver() cdevDriver { return &freebsdCdev{} }

func (c *freebsdCdev) Open(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.f = f
	c.mu.Unlock()
	return nil
}

func (c *freebsdCdev) ReadEvent() ([]byte, error) {
	c.mu.Lock()
	f := c.f
	c.mu.Unlock()
	if f == nil {
		return nil, ErrStopped
	}
	buf := make([]byte, tfEventSize)
	n, err := io.ReadFull(f, buf)
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil, ErrStopped
		}
		return nil, err
	}
	if n != tfEventSize {
		return nil, errors.New("short read from cdev")
	}
	return buf, nil
}

func (c *freebsdCdev) WriteVerdict(b []byte) error {
	c.mu.Lock()
	f := c.f
	c.mu.Unlock()
	if f == nil {
		return ErrStopped
	}
	_, err := f.Write(b)
	return err
}

func (c *freebsdCdev) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return nil
	}
	err := c.f.Close()
	c.f = nil
	return err
}
