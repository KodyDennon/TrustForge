// SPDX-License-Identifier: Apache-2.0
//
// Bridge between the FreeBSD MAC cdev and the TrustForge daemon.
//
// Wire format mirrors kernel/mac_trustforge.c:
//
//	struct tf_event   { magic='TFEV', version=1, cookie, kind,
//	                    pid, uid, gid, mask, target_pid, target_sig,
//	                    path_len, path[512] };
//	struct tf_verdict { magic='TFVD', version=1, cookie,
//	                    result, _reserved };
//
// Both records are packed little-endian (FreeBSD's MAC fwk runs on
// LE hosts in our supported configurations: amd64, arm64).

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	tfEventMagic   uint32 = 0x54464556 // 'TFEV'
	tfVerdictMagic uint32 = 0x54465644 // 'TFVD'
	tfMaxPath             = 512
	tfEventSize           = 4 + 4 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + tfMaxPath
	tfVerdictSize         = 4 + 4 + 8 + 4 + 4
)

const (
	kindVnodeOpen     uint32 = 1
	kindVnodeExec     uint32 = 2
	kindSocketConnect uint32 = 3
	kindProcSignal    uint32 = 4
)

// TFEvent is the parsed in-Go form of struct tf_event.
type TFEvent struct {
	Magic     uint32
	Version   uint32
	Cookie    uint64
	Kind      uint32
	PID       uint32
	UID       uint32
	GID       uint32
	Mask      uint32
	TargetPID uint32
	TargetSig uint32
	Path      string
}

// TFVerdict is the parsed in-Go form of struct tf_verdict.
type TFVerdict struct {
	Cookie uint64
	Result int32
}

// kindName turns the wire enum into a stable string for the daemon.
func kindName(k uint32) string {
	switch k {
	case kindVnodeOpen:
		return "vnode_open"
	case kindVnodeExec:
		return "vnode_exec"
	case kindSocketConnect:
		return "socket_connect"
	case kindProcSignal:
		return "proc_signal"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
}

// DecodeEvent parses a tf_event from the cdev's raw byte stream.
func DecodeEvent(raw []byte) (*TFEvent, error) {
	if len(raw) < tfEventSize {
		return nil, fmt.Errorf("short event: got %d bytes, want %d", len(raw), tfEventSize)
	}
	r := bytes.NewReader(raw[:tfEventSize])
	ev := &TFEvent{}
	if err := binary.Read(r, binary.LittleEndian, &ev.Magic); err != nil {
		return nil, err
	}
	if ev.Magic != tfEventMagic {
		return nil, fmt.Errorf("bad event magic: 0x%08x", ev.Magic)
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.Cookie); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.Kind); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.UID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.GID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.Mask); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.TargetPID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &ev.TargetSig); err != nil {
		return nil, err
	}
	var pathLen uint32
	if err := binary.Read(r, binary.LittleEndian, &pathLen); err != nil {
		return nil, err
	}
	pathBuf := make([]byte, tfMaxPath)
	if _, err := io.ReadFull(r, pathBuf); err != nil {
		return nil, err
	}
	if pathLen > tfMaxPath {
		pathLen = tfMaxPath
	}
	if i := bytes.IndexByte(pathBuf[:pathLen], 0); i >= 0 {
		pathLen = uint32(i)
	}
	ev.Path = string(pathBuf[:pathLen])
	return ev, nil
}

// EncodeVerdict serialises a tf_verdict to its wire form.
func EncodeVerdict(v TFVerdict) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, tfVerdictSize))
	binary.Write(buf, binary.LittleEndian, tfVerdictMagic)
	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, v.Cookie)
	binary.Write(buf, binary.LittleEndian, v.Result)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

// DecisionClient asks the TrustForge daemon for an allow/deny verdict.
type DecisionClient interface {
	Decide(ctx context.Context, ev *TFEvent) (int32, error)
}

// httpDecider talks to tf-daemon /v1/decide over HTTP or unix-socket HTTP.
type httpDecider struct {
	url    string
	client *http.Client
	logger *log.Logger
}

func newDecider(daemon string, timeoutMs int, logger *log.Logger) (DecisionClient, error) {
	u, err := url.Parse(daemon)
	if err != nil {
		return nil, fmt.Errorf("invalid --daemon URL %q: %w", daemon, err)
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	tr := &http.Transport{}
	if u.Scheme == "unix" || strings.HasPrefix(daemon, "/") {
		path := daemon
		if u.Scheme == "unix" {
			path = u.Path
		}
		tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", path, timeout)
		}
		// Use a synthetic http URL so the transport routes correctly.
		return &httpDecider{
			url:    "http://unix/v1/decide",
			client: &http.Client{Transport: tr, Timeout: timeout},
			logger: logger,
		}, nil
	}
	return &httpDecider{
		url:    daemon,
		client: &http.Client{Transport: tr, Timeout: timeout},
		logger: logger,
	}, nil
}

type decideRequest struct {
	V         int    `json:"v"`
	Cookie    uint64 `json:"cookie"`
	Kind      string `json:"kind"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Mask      uint32 `json:"mask"`
	TargetPID uint32 `json:"target_pid,omitempty"`
	TargetSig uint32 `json:"target_sig,omitempty"`
	Path      string `json:"path,omitempty"`
	Platform  string `json:"platform"`
}

type decideResponse struct {
	Result int32 `json:"result"`
}

func (h *httpDecider) Decide(ctx context.Context, ev *TFEvent) (int32, error) {
	req := decideRequest{
		V: 1, Cookie: ev.Cookie, Kind: kindName(ev.Kind),
		PID: ev.PID, UID: ev.UID, GID: ev.GID, Mask: ev.Mask,
		TargetPID: ev.TargetPID, TargetSig: ev.TargetSig,
		Path:     ev.Path,
		Platform: "freebsd-mac",
	}
	body, err := json.Marshal(&req)
	if err != nil {
		return 0, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(hr)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("daemon %s returned %d", h.url, resp.StatusCode)
	}
	var dr decideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return 0, err
	}
	return dr.Result, nil
}

// Bridge owns the cdev fd, the decision client, and the lifecycle.
type Bridge struct {
	device    string
	failOpen  bool
	logger    *log.Logger
	decision  DecisionClient
	timeout   time.Duration
	stopFlag  atomic.Bool
	driver    cdevDriver
	processed atomic.Uint64
	allows    atomic.Uint64
	denies    atomic.Uint64
}

// cdevDriver abstracts the platform-specific reading of /dev/mac_trustforge.
type cdevDriver interface {
	Open(path string) error
	ReadEvent() ([]byte, error)
	WriteVerdict([]byte) error
	Close() error
}

// NewBridge wires together the decider and the (platform-specific) cdev
// driver.
func NewBridge(device, daemon string, timeoutMs int, failOpen bool, logger *log.Logger) (*Bridge, error) {
	decider, err := newDecider(daemon, timeoutMs, logger)
	if err != nil {
		return nil, err
	}
	br := &Bridge{
		device:   device,
		failOpen: failOpen,
		logger:   logger,
		decision: decider,
		timeout:  time.Duration(timeoutMs) * time.Millisecond,
		driver:   newCdevDriver(),
	}
	if err := br.driver.Open(device); err != nil {
		return nil, fmt.Errorf("open %s: %w", device, err)
	}
	return br, nil
}

// Run is the read/decide/write loop. It returns nil after Stop() is
// called and the cdev returns ErrStopped.
func (b *Bridge) Run() error {
	for !b.stopFlag.Load() {
		raw, err := b.driver.ReadEvent()
		if err != nil {
			if errors.Is(err, ErrStopped) {
				return nil
			}
			b.logger.Printf("read error: %v", err)
			continue
		}
		ev, err := DecodeEvent(raw)
		if err != nil {
			b.logger.Printf("decode error: %v", err)
			continue
		}
		b.processed.Add(1)
		ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
		result, derr := b.decision.Decide(ctx, ev)
		cancel()
		if derr != nil {
			b.logger.Printf("decide(cookie=%d kind=%s) error: %v",
				ev.Cookie, kindName(ev.Kind), derr)
			if b.failOpen {
				result = 0
			} else {
				result = 13 // EACCES
			}
		}
		if result == 0 {
			b.allows.Add(1)
		} else {
			b.denies.Add(1)
		}
		out := EncodeVerdict(TFVerdict{Cookie: ev.Cookie, Result: result})
		if err := b.driver.WriteVerdict(out); err != nil {
			b.logger.Printf("write verdict cookie=%d: %v", ev.Cookie, err)
		}
	}
	return nil
}

// Stop interrupts Run() at the next read boundary.
func (b *Bridge) Stop() {
	b.stopFlag.Store(true)
	_ = b.driver.Close()
}

// Close releases the cdev.
func (b *Bridge) Close() error { return b.driver.Close() }

// Stats returns processed/allow/deny counters; primarily for tests.
func (b *Bridge) Stats() (processed, allows, denies uint64) {
	return b.processed.Load(), b.allows.Load(), b.denies.Load()
}

// ErrStopped is returned from ReadEvent when the bridge is shutting down.
var ErrStopped = errors.New("bridge stopped")
