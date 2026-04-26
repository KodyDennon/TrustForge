// SPDX-License-Identifier: Apache-2.0 OR MIT
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMacToActorURI_LowercasesAndPrefixes(t *testing.T) {
	got := macToActorURI("AA:BB:CC:DD:EE:FF")
	want := "tf:actor:host:unifi/aa:bb:cc:dd:ee:ff"
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestMacToActorURI_EmptyFallsBackToUnknown(t *testing.T) {
	got := macToActorURI("   ")
	if got != "tf:actor:host:unifi/unknown" {
		t.Fatalf("got=%q", got)
	}
}

func TestMacToFilename_ColonsToDashes(t *testing.T) {
	got := macToFilename("AA:BB:CC:DD:EE:FF")
	if got != "aa-bb-cc-dd-ee-ff.yaml" {
		t.Fatalf("got=%q", got)
	}
}

func TestRenderClientManifest_StableShape(t *testing.T) {
	out := renderClientManifest(
		Client{Mac: "AA:BB:CC:DD:EE:FF", Hostname: "phone", IP: "10.0.0.5", Network: "guest"},
		DecideResponse{Decision: "allow", Reason: ""},
	)
	for _, want := range []string{
		"actor: tf:actor:host:unifi/aa:bb:cc:dd:ee:ff",
		"hostname: \"phone\"",
		"network: \"guest\"",
		"current: \"allow\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderDeviceManifest_StableShape(t *testing.T) {
	out := renderDeviceManifest(
		Device{Mac: "00:11:22:33:44:55", Name: "ap-lobby", Type: "uap", Model: "U6-LR", Adopted: true},
		DecideResponse{Decision: "allow"},
	)
	for _, want := range []string{
		"actor: tf:actor:device:unifi/00:11:22:33:44:55",
		"adopted: true",
		"current: \"allow\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest missing %q\n---\n%s", want, out)
		}
	}
}

func TestWriteManifest_AtomicAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := writeManifest(dir, "foo.yaml", "hello\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, "foo.yaml", "hello again\n"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "foo.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello again\n" {
		t.Fatalf("got=%q", got)
	}
}

func TestReconcile_FullPath(t *testing.T) {
	// Mock UniFi controller with one client and one device.
	mockController := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/stat/sta"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []Client{{Mac: "AA:BB:CC:00:00:01", Hostname: "alice-laptop", IP: "10.0.0.10", Network: "lan"}},
			})
		case strings.HasSuffix(r.URL.Path, "/stat/device"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"meta": map[string]string{"rc": "ok"},
				"data": []Device{{Mac: "00:11:22:33:44:55", Name: "ap-lobby", Type: "uap", Adopted: true}},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer mockController.Close()

	// Mock tf-daemon.
	mockDaemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Decision: "allow"})
	}))
	defer mockDaemon.Close()

	u, err := NewUniFi(mockController.URL, "default", "u", "p", false)
	if err != nil {
		t.Fatal(err)
	}
	dec := NewDecider(mockDaemon.URL)

	dir := t.TempDir()
	if err := reconcile(context.Background(), u, dec, dir); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	clientYaml, err := os.ReadFile(filepath.Join(dir, "clients", "aa-bb-cc-00-00-01.yaml"))
	if err != nil {
		t.Fatalf("client manifest missing: %v", err)
	}
	if !strings.Contains(string(clientYaml), "alice-laptop") {
		t.Errorf("client manifest missing hostname: %s", clientYaml)
	}

	deviceYaml, err := os.ReadFile(filepath.Join(dir, "devices", "00-11-22-33-44-55.yaml"))
	if err != nil {
		t.Fatalf("device manifest missing: %v", err)
	}
	if !strings.Contains(string(deviceYaml), "ap-lobby") {
		t.Errorf("device manifest missing name: %s", deviceYaml)
	}
}

func TestDecider_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Decision: "allow"})
	}))
	defer srv.Close()
	d := NewDecider(srv.URL)
	resp, err := d.Decide(context.Background(), DecideRequest{Actor: "x", Action: "y", Target: "z"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("got=%v", resp)
	}
}
