// SPDX-License-Identifier: Apache-2.0
//
// tf-ebpf-loader
//
// Loads the TrustForge BPF LSM / cgroup programs (compiled to .o by
// the top-level Makefile), pins the shared maps under
// /sys/fs/bpf/trustforge, attaches each program to its hook, drains
// the ring buffer, calls the local TrustForge daemon over a Unix
// socket for each event, and writes verdicts back into verdict_map.
//
// Build:  go build ./cmd/tf-ebpf-loader
// Run:    sudo ./tf-ebpf-loader \
//             --obj-dir ../.. \
//             --daemon  /run/trustforge/decide.sock \
//             --cgroup  /sys/fs/cgroup
//
// Requires: kernel >= 5.7 with CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y,
// and `lsm=...,bpf` on the kernel cmdline (so the BPF LSM is enabled).

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Wire-compatible with progs/*.bpf.c: tf_event_t.
type tfEvent struct {
	Cookie uint64
	Kind   uint32
	PID    uint32
	UID    uint32
	GID    uint32
	Mask   uint32
	Comm   [16]byte
	Path   [256]byte
}

const (
	pinDir         = "/sys/fs/bpf/trustforge"
	verdictMapName = "verdict_map"
	eventsMapName  = "events"
	cookieMapName  = "cookie_ctr"
)

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

type decideRequest struct {
	V      int    `json:"v"`
	Cookie uint64 `json:"cookie"`
	Kind   uint32 `json:"kind"`
	PID    uint32 `json:"pid"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mask   uint32 `json:"mask"`
	Comm   string `json:"comm"`
	Path   string `json:"path"`
}

type decideResponse struct {
	Result int32 `json:"result"`
}

func decide(daemon string, ev *tfEvent) int32 {
	c, err := net.DialTimeout("unix", daemon, 50*time.Millisecond)
	if err != nil {
		log.Printf("daemon dial: %v (fail-open)", err)
		return 0
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(80 * time.Millisecond))

	req := decideRequest{
		V:      1,
		Cookie: ev.Cookie,
		Kind:   ev.Kind,
		PID:    ev.PID,
		UID:    ev.UID,
		GID:    ev.GID,
		Mask:   ev.Mask,
		Comm:   cstr(ev.Comm[:]),
		Path:   cstr(ev.Path[:]),
	}
	enc := json.NewEncoder(c)
	if err := enc.Encode(&req); err != nil {
		log.Printf("daemon encode: %v (fail-open)", err)
		return 0
	}
	resp := decideResponse{}
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&resp); err != nil {
		log.Printf("daemon decode: %v (fail-open)", err)
		return 0
	}
	return resp.Result
}

// loadAndPinShared loads the first object so the shared maps
// (events / verdict_map / cookie_ctr) are created and pinned. All
// subsequent objects reuse those pinned maps.
func loadAndPinShared(objPath string) (*ebpf.Collection, error) {
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load spec %s: %w", objPath, err)
	}
	for _, name := range []string{eventsMapName, verdictMapName, cookieMapName} {
		if m, ok := spec.Maps[name]; ok {
			m.Pinning = ebpf.PinByName
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	})
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	return coll, nil
}

// loadReusing opens a second/third object and reuses the already-pinned
// shared maps so all programs publish to the same ringbuf.
func loadReusing(objPath string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load spec %s: %w", objPath, err)
	}
	for _, name := range []string{eventsMapName, verdictMapName, cookieMapName} {
		if m, ok := spec.Maps[name]; ok {
			m.Pinning = ebpf.PinByName
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	})
	if err != nil {
		return nil, fmt.Errorf("new collection (reuse): %w", err)
	}
	return coll, nil
}

func attachLSM(coll *ebpf.Collection) ([]link.Link, error) {
	var links []link.Link
	for name, p := range coll.Programs {
		if p.Type() != ebpf.LSM {
			continue
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			return links, fmt.Errorf("attach LSM %s: %w", name, err)
		}
		log.Printf("attached LSM program %s", name)
		links = append(links, l)
	}
	return links, nil
}

func attachCgroup(coll *ebpf.Collection, cgroupPath string) ([]link.Link, error) {
	var links []link.Link
	for name, p := range coll.Programs {
		if p.Type() != ebpf.CGroupSockAddr {
			continue
		}
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: p,
		})
		if err != nil {
			return links, fmt.Errorf("attach cgroup %s: %w", name, err)
		}
		log.Printf("attached cgroup program %s @ %s", name, cgroupPath)
		links = append(links, l)
	}
	return links, nil
}

func writeVerdict(verdict *ebpf.Map, cookie uint64, result int32) {
	var k [8]byte
	binary.LittleEndian.PutUint64(k[:], cookie)
	if err := verdict.Update(k[:], result, ebpf.UpdateAny); err != nil {
		log.Printf("verdict map update: %v", err)
	}
}

func main() {
	objDir := flag.String("obj-dir", ".", "directory containing *.bpf.o objects")
	daemon := flag.String("daemon", "/run/trustforge/decide.sock",
		"unix socket of the TrustForge policy daemon")
	cgroup := flag.String("cgroup", "/sys/fs/cgroup",
		"cgroup v2 mount point for cgroup programs")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	primary := filepath.Join(*objDir, "lsm_inode_permission.bpf.o")
	other := []string{
		filepath.Join(*objDir, "lsm_socket_connect.bpf.o"),
		filepath.Join(*objDir, "lsm_bprm_check.bpf.o"),
		filepath.Join(*objDir, "lsm_file_open.bpf.o"),
		filepath.Join(*objDir, "cgroup_sock_connect.bpf.o"),
	}

	first, err := loadAndPinShared(primary)
	if err != nil {
		log.Fatalf("primary load: %v", err)
	}
	defer first.Close()

	colls := []*ebpf.Collection{first}
	for _, o := range other {
		if _, err := os.Stat(o); errors.Is(err, os.ErrNotExist) {
			log.Printf("skip missing object %s", o)
			continue
		}
		c, err := loadReusing(o)
		if err != nil {
			log.Printf("load %s: %v", o, err)
			continue
		}
		colls = append(colls, c)
	}

	var allLinks []link.Link
	for _, c := range colls {
		ls, err := attachLSM(c)
		if err != nil {
			log.Printf("attachLSM: %v", err)
		}
		allLinks = append(allLinks, ls...)

		cgs, err := attachCgroup(c, *cgroup)
		if err != nil {
			log.Printf("attachCgroup: %v", err)
		}
		allLinks = append(allLinks, cgs...)
	}
	defer func() {
		for _, l := range allLinks {
			_ = l.Close()
		}
	}()

	events := first.Maps[eventsMapName]
	verdict := first.Maps[verdictMapName]
	if events == nil || verdict == nil {
		log.Fatalf("shared maps missing from primary collection")
	}

	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	log.Printf("tf-ebpf-loader running; daemon=%s cgroup=%s", *daemon, *cgroup)

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("ringbuf closed; exiting")
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		if len(rec.RawSample) < int(unsafeSize()) {
			continue
		}
		var ev tfEvent
		if err := readEvent(rec.RawSample, &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		go func(e tfEvent) {
			r := decide(*daemon, &e)
			writeVerdict(verdict, e.Cookie, r)
		}(ev)
	}
}

// unsafeSize returns the size of tfEvent for sanity-checking ringbuf reads.
func unsafeSize() uintptr {
	var e tfEvent
	return uintptrSizeOf(e)
}

func uintptrSizeOf(_ tfEvent) uintptr {
	// Compile-time-known: 8 + 4*5 + 16 + 256 = 300 bytes.
	return 8 + 4 + 4 + 4 + 4 + 4 + 16 + 256
}

func readEvent(raw []byte, ev *tfEvent) error {
	if len(raw) < int(uintptrSizeOf(*ev)) {
		return fmt.Errorf("short record: %d bytes", len(raw))
	}
	ev.Cookie = binary.LittleEndian.Uint64(raw[0:8])
	ev.Kind = binary.LittleEndian.Uint32(raw[8:12])
	ev.PID = binary.LittleEndian.Uint32(raw[12:16])
	ev.UID = binary.LittleEndian.Uint32(raw[16:20])
	ev.GID = binary.LittleEndian.Uint32(raw[20:24])
	ev.Mask = binary.LittleEndian.Uint32(raw[24:28])
	copy(ev.Comm[:], raw[28:44])
	copy(ev.Path[:], raw[44:300])
	return nil
}
