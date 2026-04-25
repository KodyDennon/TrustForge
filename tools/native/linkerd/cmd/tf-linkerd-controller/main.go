// SPDX-License-Identifier: Apache-2.0
//
// tf-linkerd-controller — watches Linkerd Server CRs and synchronises a
// matching ServerAuthorization whose allowed mesh-TLS identities reflect
// the latest verdict from the TrustForge daemon.
//
// The controller treats Server / ServerAuthorization as
// `unstructured.Unstructured` so we don't have to vendor the heavyweight
// Linkerd Go module just to read a few fields.
//
// Status: Draft (Phase 0). Not production-ready. The reference tf-daemon
// is not yet shipped.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ServerGVR / ServerAuthorizationGVR are the Linkerd policy CRDs.
var (
	ServerGVR = schema.GroupVersionResource{
		Group:    "policy.linkerd.io",
		Version:  "v1beta1",
		Resource: "servers",
	}
	ServerAuthorizationGVR = schema.GroupVersionResource{
		Group:    "policy.linkerd.io",
		Version:  "v1beta1",
		Resource: "serverauthorizations",
	}
)

// DecideRequest is the wire shape of POST /v1/decide.
type DecideRequest struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// DecideResponse is what tf-daemon returns. `identities` is a
// TrustForge-specific field carrying the SPIFFE-shaped IDs the daemon
// believes are currently authorised to talk to the target Server.
type DecideResponse struct {
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason,omitempty"`
	Identities []string `json:"identities,omitempty"`
}

// DaemonClient calls /v1/decide.
type DaemonClient struct {
	URL  string
	HTTP *http.Client
}

// Decide POSTs a DecideRequest and returns the daemon's verdict.
func (c *DaemonClient) Decide(ctx context.Context, req DecideRequest) (*DecideResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("daemon round-trip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon returned %d: %s", resp.StatusCode, string(raw))
	}
	var dr DecideResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &dr, nil
}

// Reconciler is the testable core. It walks every Server, asks the
// TrustForge daemon for an allow-list of identities, and ensures a
// matching ServerAuthorization (named `<server>-trustforge`) exists in
// the same namespace.
type Reconciler struct {
	Client dynamic.Interface
	Daemon *DaemonClient
}

// reconcileAll lists all Servers cluster-wide.
func (r *Reconciler) reconcileAll(ctx context.Context) (int, error) {
	list, err := r.Client.Resource(ServerGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list Servers: %w", err)
	}
	processed := 0
	for i := range list.Items {
		s := &list.Items[i]
		if err := r.reconcileOne(ctx, s); err != nil {
			log.Printf("reconcile %s/%s: %v", s.GetNamespace(), s.GetName(), err)
			continue
		}
		processed++
	}
	return processed, nil
}

// reconcileOne asks tf-daemon what identities should reach the given
// Server, then upserts a matching ServerAuthorization.
func (r *Reconciler) reconcileOne(ctx context.Context, srv *unstructured.Unstructured) error {
	target := srv.GetNamespace() + "/" + srv.GetName()
	resp, err := r.Daemon.Decide(ctx, DecideRequest{
		Actor:  "linkerd-controller",
		Action: "linkerd.authz.server",
		Target: target,
	})
	if err != nil {
		// Fail-closed: empty identities = nobody allowed.
		return r.upsertAuthorization(ctx, srv, nil, "DaemonError: "+err.Error())
	}
	identities := resp.Identities
	if resp.Decision != "allow" {
		identities = nil
	}
	return r.upsertAuthorization(ctx, srv, identities, resp.Reason)
}

// upsertAuthorization creates-or-updates the ServerAuthorization that
// shadows `srv`. The name is `<server>-trustforge`.
func (r *Reconciler) upsertAuthorization(ctx context.Context, srv *unstructured.Unstructured, identities []string, reason string) error {
	name := srv.GetName() + "-trustforge"
	ns := srv.GetNamespace()

	authz := buildServerAuthorization(name, ns, srv.GetName(), identities, reason)

	res := r.Client.Resource(ServerAuthorizationGVR).Namespace(ns)
	cur, err := res.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// Not found → create.
		if _, err2 := res.Create(ctx, authz, metav1.CreateOptions{}); err2 != nil {
			return fmt.Errorf("create ServerAuthorization: %w", err2)
		}
		return nil
	}
	authz.SetResourceVersion(cur.GetResourceVersion())
	if _, err := res.Update(ctx, authz, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update ServerAuthorization: %w", err)
	}
	return nil
}

// buildServerAuthorization returns a freshly-constructed Unstructured
// ready to feed into create/update. Exported indirectly via the test
// helpers.
func buildServerAuthorization(name, ns, serverName string, identities []string, reason string) *unstructured.Unstructured {
	if identities == nil {
		identities = []string{}
	}
	ids := make([]interface{}, 0, len(identities))
	for _, id := range identities {
		ids = append(ids, id)
	}
	obj := &unstructured.Unstructured{}
	obj.SetUnstructuredContent(map[string]interface{}{
		"apiVersion": "policy.linkerd.io/v1beta1",
		"kind":       "ServerAuthorization",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": ns,
			"annotations": map[string]interface{}{
				"trustforge.io/managed": "true",
				"trustforge.io/reason":  reason,
			},
		},
		"spec": map[string]interface{}{
			"server": map[string]interface{}{
				"name": serverName,
			},
			"client": map[string]interface{}{
				"meshTLS": map[string]interface{}{
					"identities": ids,
				},
			},
		},
	})
	return obj
}

// run is a polling loop. A production controller would use informers.
func (r *Reconciler) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		n, err := r.reconcileAll(ctx)
		if err != nil {
			log.Printf("reconcileAll: %v", err)
		} else {
			log.Printf("reconciled %d Servers", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func main() {
	var (
		kubeconfig = flag.String("kubeconfig", "", "path to kubeconfig (empty = in-cluster)")
		daemonURL  = flag.String("daemon-url", envOr("TF_DAEMON_URL", "http://127.0.0.1:8765"), "tf-daemon base URL")
		interval   = flag.Duration("interval", 30*time.Second, "reconcile poll interval")
	)
	flag.Parse()

	cfg, err := loadConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("dynamic client: %v", err)
	}

	r := &Reconciler{
		Client: dyn,
		Daemon: &DaemonClient{URL: *daemonURL, HTTP: &http.Client{Timeout: 5 * time.Second}},
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("tf-linkerd-controller starting (daemon=%s, interval=%s)", *daemonURL, *interval)
	r.run(ctx, *interval)
	log.Print("tf-linkerd-controller exiting")
}

func loadConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	return clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
