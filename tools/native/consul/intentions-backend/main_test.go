// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockDaemon(t *testing.T, want *DecideRequest, reply DecideResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		var got DecideRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if want != nil {
			*want = got
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
}

func TestHandleCheck_Allow(t *testing.T) {
	var seen DecideRequest
	d := mockDaemon(t, &seen, DecideResponse{Decision: "allow"})
	defer d.Close()

	b := NewBackend(d.URL)
	body, _ := json.Marshal(IntentionCheckRequest{Source: "web", Destination: "db"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/intention/check", bytes.NewReader(body))
	b.HandleCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp IntentionCheckResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("expected Allowed=true, got %+v", resp)
	}
	if seen.Actor != "web" || seen.Target != "db" || seen.Action != "consul.connect.dial" {
		t.Fatalf("daemon saw wrong fields: %+v", seen)
	}
}

func TestHandleCheck_DenyWithReason(t *testing.T) {
	d := mockDaemon(t, nil, DecideResponse{Decision: "deny", Reason: "intent not allowed"})
	defer d.Close()
	b := NewBackend(d.URL)
	body, _ := json.Marshal(IntentionCheckRequest{Source: "web", Destination: "db"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/intention/check", bytes.NewReader(body))
	b.HandleCheck(rec, req)

	var resp IntentionCheckResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatalf("expected Allowed=false, got %+v", resp)
	}
	if !strings.Contains(resp.Reason, "intent not allowed") {
		t.Fatalf("reason missing: %v", resp.Reason)
	}
}

func TestHandleCheck_FailClosedOnDaemonError(t *testing.T) {
	b := NewBackend("http://127.0.0.1:1") // unused port
	body, _ := json.Marshal(IntentionCheckRequest{Source: "web", Destination: "db"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/intention/check", bytes.NewReader(body))
	b.HandleCheck(rec, req)

	var resp IntentionCheckResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatalf("expected fail-closed, got %+v", resp)
	}
}

func TestHandleCheck_QueryStringForm(t *testing.T) {
	d := mockDaemon(t, nil, DecideResponse{Decision: "allow"})
	defer d.Close()
	b := NewBackend(d.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/intention/check?source=web&destination=db", nil)
	b.HandleCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp IntentionCheckResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatalf("expected Allowed=true, got %+v", resp)
	}
}
