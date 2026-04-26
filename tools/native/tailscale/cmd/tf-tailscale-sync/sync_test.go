// SPDX-License-Identifier: Apache-2.0 OR MIT
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeKeyPrefix_TrimsAndShortens(t *testing.T) {
	got := nodeKeyPrefix("nodekey:abcdef0123456789abcd")
	if got != "abcdef012345" {
		t.Fatalf("got=%q", got)
	}
}

func TestNodeKeyPrefix_NoPrefixShortKey(t *testing.T) {
	got := nodeKeyPrefix("short")
	if got != "short" {
		t.Fatalf("got=%q", got)
	}
}

func TestPeerToDecideRequest_Shape(t *testing.T) {
	r := peerToDecideRequest(&Peer{NodeKey: "nodekey:abcdef0123456789aaaa", HostName: "alice-laptop"}, "my-host")
	if r.Actor != "tf:actor:host:tailscale/abcdef012345" {
		t.Fatalf("actor=%q", r.Actor)
	}
	if r.Action != "tailscale.peer.connect" {
		t.Fatalf("action=%q", r.Action)
	}
	if r.Target != "my-host" {
		t.Fatalf("target=%q", r.Target)
	}
}

func mockDaemon(reply DecideResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
}

func TestReconcilePeer_AllowDoesNotErr(t *testing.T) {
	d := mockDaemon(DecideResponse{Decision: "allow"})
	defer d.Close()
	dec := NewDecider(d.URL)
	resp, err := reconcilePeer(context.Background(), dec, &Peer{NodeKey: "nodekey:abcdef0123456789", HostName: "h"}, "self", true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("got=%v", resp)
	}
}

func TestReconcilePeer_FailClosedOnDaemonError(t *testing.T) {
	dec := NewDecider("http://127.0.0.1:1") // unused port
	resp, err := reconcilePeer(context.Background(), dec, &Peer{NodeKey: "nodekey:zzz"}, "self", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected deny on fail-closed, got=%v", resp)
	}
}

func TestReconcilePeer_FailOpenOnDaemonError(t *testing.T) {
	dec := NewDecider("http://127.0.0.1:1") // unused port
	resp, err := reconcilePeer(context.Background(), dec, &Peer{NodeKey: "nodekey:zzz"}, "self", false)
	if err == nil {
		t.Fatal("expected error")
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow on fail-open, got=%v", resp)
	}
}

func TestReconcilePeer_NilPeer(t *testing.T) {
	dec := NewDecider("http://127.0.0.1:1")
	if _, err := reconcilePeer(context.Background(), dec, nil, "self", true); err == nil {
		t.Fatal("expected error on nil peer")
	}
}

func TestSSHAuthListener_AllowReturns200(t *testing.T) {
	d := mockDaemon(DecideResponse{Decision: "allow"})
	defer d.Close()
	dec := NewDecider(d.URL)

	mux := http.NewServeMux()
	mux.HandleFunc("/trustforge/ssh/auth", func(w http.ResponseWriter, r *http.Request) {
		var ar SSHAuthRequest
		_ = json.NewDecoder(r.Body).Decode(&ar)
		req := DecideRequest{
			Actor:  "tf:actor:user:tailscale/" + ar.UserLogin,
			Action: "tailscale.ssh.connect",
			Target: "self",
		}
		resp, err := dec.Decide(r.Context(), req)
		if err != nil {
			writeSSHResp(w, SSHAuthResponse{Allow: false, Reason: err.Error()})
			return
		}
		writeSSHResp(w, SSHAuthResponse{Allow: resp.Decision == "allow"})
	})

	body, _ := json.Marshal(SSHAuthRequest{UserLogin: "alice@example.com"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/trustforge/ssh/auth", bytes.NewReader(body))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var ar SSHAuthResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &ar)
	if !ar.Allow {
		t.Fatalf("expected Allow=true, got %+v", ar)
	}
}

func TestSSHAuthListener_DenyReturns403(t *testing.T) {
	d := mockDaemon(DecideResponse{Decision: "deny", Reason: "off-hours"})
	defer d.Close()
	dec := NewDecider(d.URL)

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(SSHAuthRequest{UserLogin: "bob@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/trustforge/ssh/auth", bytes.NewReader(body))

	// Reuse the listener handler shape inline.
	resp, err := dec.Decide(req.Context(), DecideRequest{
		Actor:  "tf:actor:user:tailscale/" + "bob@example.com",
		Action: "tailscale.ssh.connect",
		Target: "self",
	})
	if err != nil {
		t.Fatal(err)
	}
	writeSSHResp(rec, SSHAuthResponse{Allow: resp.Decision == "allow", Reason: resp.Reason})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "off-hours") {
		t.Fatalf("missing reason: %s", rec.Body.String())
	}
}

func TestDecider_HappyPath(t *testing.T) {
	d := mockDaemon(DecideResponse{Decision: "allow"})
	defer d.Close()
	dec := NewDecider(d.URL)
	resp, err := dec.Decide(context.Background(), DecideRequest{Actor: "x", Action: "y", Target: "z"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("got=%v", resp)
	}
}

func TestStatus_Decode(t *testing.T) {
	raw := []byte(`{"BackendState":"Running","Self":{"PublicKey":"nodekey:aa"},"Peer":{"k":{"PublicKey":"nodekey:bb","HostName":"h","Online":true,"TailscaleIPs":["100.64.0.2"]}}}`)
	var s Status
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.Self.NodeKey != "nodekey:aa" {
		t.Fatalf("self=%+v", s.Self)
	}
	p, ok := s.Peer["k"]
	if !ok {
		t.Fatal("missing peer")
	}
	if !p.Online || p.HostName != "h" {
		t.Fatalf("peer=%+v", p)
	}
}
