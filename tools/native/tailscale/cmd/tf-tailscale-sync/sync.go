// SPDX-License-Identifier: Apache-2.0 OR MIT
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// nodeKeyPrefix returns a short, log-safe prefix of a Tailscale
// NodeKey suitable for use inside an actor URI. Tailscale keys are
// long base64; we keep the first 12 chars after the "nodekey:"
// prefix so tf:actor: stays human-skimmable.
func nodeKeyPrefix(key string) string {
	k := strings.TrimPrefix(key, "nodekey:")
	if len(k) > 12 {
		return k[:12]
	}
	return k
}

// peerToDecideRequest is the pure mapping. Exported for tests.
func peerToDecideRequest(peer *Peer, ourHost string) DecideRequest {
	return DecideRequest{
		Actor:  "tf:actor:host:tailscale/" + nodeKeyPrefix(peer.NodeKey),
		Action: "tailscale.peer.connect",
		Target: ourHost,
	}
}

// reconcilePeer is one decision pass for a single peer; broken out
// for testability.
func reconcilePeer(ctx context.Context, dec *Decider, peer *Peer, ourHost string, failClosed bool) (*DecideResponse, error) {
	if peer == nil {
		return nil, fmt.Errorf("nil peer")
	}
	resp, err := dec.Decide(ctx, peerToDecideRequest(peer, ourHost))
	if err != nil {
		if failClosed {
			return &DecideResponse{Decision: "deny", Reason: err.Error()}, err
		}
		return &DecideResponse{Decision: "allow", Reason: err.Error()}, err
	}
	return resp, nil
}

// runWatcher drives the long-running watch loop. On every IPN-bus
// event we fetch a fresh status and reconcile each peer.
func runWatcher(ctx context.Context, tc *LocalClient, dec *Decider, ourHost string, failClosed bool) error {
	// Seed pass: reconcile whatever peers we can see at startup.
	if status, err := tc.Status(ctx); err == nil {
		for _, p := range status.Peer {
			if !p.Online {
				continue
			}
			if r, err := reconcilePeer(ctx, dec, p, ourHost, failClosed); err != nil {
				log.Printf("seed peer %s: %v (decision=%s)", p.HostName, err, r.Decision)
			} else {
				log.Printf("seed peer %s decision=%s", p.HostName, r.Decision)
			}
		}
	} else {
		log.Printf("seed status fetch failed: %v", err)
	}

	// Stream events. If the watch endpoint disconnects we re-arm.
	for {
		err := tc.WatchIPNBus(ctx, func(event []byte) error {
			// On any event, refresh status and reconcile.
			st, err := tc.Status(ctx)
			if err != nil {
				log.Printf("post-event status: %v", err)
				return nil
			}
			for _, p := range st.Peer {
				if !p.Online {
					continue
				}
				resp, err := reconcilePeer(ctx, dec, p, ourHost, failClosed)
				if err != nil {
					log.Printf("peer %s decide error: %v (decision=%s)", p.HostName, err, resp.Decision)
				} else {
					log.Printf("peer %s decision=%s", p.HostName, resp.Decision)
				}
			}
			return nil
		})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("watch-ipn-bus: %v; reconnecting in 3s", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(3 * time.Second):
			}
		}
	}
}

// SSHAuthRequest mirrors the (informally documented) shape Tailscale
// SSH posts to an external auth-hook URL. The keys here match the
// fields the tailscaled forwarder sets when `ExternalAuthURL` is
// configured.
type SSHAuthRequest struct {
	NodeKey   string   `json:"node_key"`
	UserLogin string   `json:"user_login"`
	HostName  string   `json:"host_name"`
	IP        string   `json:"ip"`
	SrcIPs    []string `json:"src_ips"`
}

// SSHAuthResponse is what we hand back. Tailscale SSH expects
// {"allow": bool, "reason": "..."} so we serialise to that shape.
type SSHAuthResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// runSSHAuthListener stands up the tiny HTTP server the Tailscale-SSH
// OnAuthRequest hook calls. It blocks; spawn it in a goroutine.
func runSSHAuthListener(addr string, dec *Decider, ourHost string, failClosed bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("/trustforge/ssh/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var ar SSHAuthRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &ar)
		req := DecideRequest{
			Actor:  fmt.Sprintf("tf:actor:user:tailscale/%s", ar.UserLogin),
			Action: "tailscale.ssh.connect",
			Target: ourHost,
		}
		resp, err := dec.Decide(r.Context(), req)
		if err != nil {
			log.Printf("ssh decide failed: %v (fail-closed=%v)", err, failClosed)
			ans := SSHAuthResponse{Allow: !failClosed, Reason: err.Error()}
			writeSSHResp(w, ans)
			return
		}
		writeSSHResp(w, SSHAuthResponse{
			Allow:  resp.Decision == "allow",
			Reason: resp.Reason,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	log.Printf("ssh auth listener on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ssh listener: %v", err)
	}
}

func writeSSHResp(w http.ResponseWriter, r SSHAuthResponse) {
	w.Header().Set("content-type", "application/json")
	if !r.Allow {
		w.WriteHeader(http.StatusForbidden)
	}
	_ = json.NewEncoder(w).Encode(r)
}
