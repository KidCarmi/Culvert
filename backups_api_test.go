package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// resetBackupsCache isolates the process-global listing cache per test.
func resetBackupsCache(t *testing.T) {
	t.Helper()
	backupsCache.mu.Lock()
	prevAt, prevPayload := backupsCache.at, backupsCache.payload
	backupsCache.at, backupsCache.payload = time.Time{}, nil
	backupsCache.mu.Unlock()
	t.Cleanup(func() {
		backupsCache.mu.Lock()
		backupsCache.at, backupsCache.payload = prevAt, prevPayload
		backupsCache.mu.Unlock()
	})
}

func callAPIBackups(t *testing.T) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/backups", http.NoBody)
	apiBackups(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w.Code, body
}

// TestAPIBackups_ListingIsSingleFlightedAndCached pins the review P1: every
// agent listing spawns a `docker compose run` container on the host and
// securityMiddleware rate-limits only mutating methods, so back-to-back
// viewer GETs must be served from the short cache — one agent round trip,
// not one container per refresh.
func TestAPIBackups_ListingIsSingleFlightedAndCached(t *testing.T) {
	resetBackupsCache(t)
	var hits atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`[{"name":"backup-1.tar.gz","size_bytes":42,"modified_at":"2026-08-20T01:00:00Z"}]`))
	}))
	defer agent.Close()
	t.Setenv(envMaintAgentURL, agent.URL)

	for i := 0; i < 3; i++ {
		code, body := callAPIBackups(t)
		if code != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200", i, code)
		}
		if body["available"] != true {
			t.Fatalf("call %d: available = %v, want true (body %v)", i, body["available"], body)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("agent hit %d times for 3 GETs inside the TTL, want exactly 1 (cache/single-flight lost)", got)
	}
}

// TestAPIBackups_AgentDownIsHTTP200Unavailable pins the review P2: the
// OpenAPI contract declares 200/403 only and the GUI's api() helper throws on
// any non-2xx (blanking the panel exactly while the operator diagnoses the
// agent), so agent-down must answer 200 {available:false} like the
// not-configured branch always did — never 503.
func TestAPIBackups_AgentDownIsHTTP200Unavailable(t *testing.T) {
	resetBackupsCache(t)
	agent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	agent.Close() // connection refused from here on
	t.Setenv(envMaintAgentURL, agent.URL)

	code, body := callAPIBackups(t)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with available:false", code)
	}
	if body["available"] != false {
		t.Fatalf("available = %v, want false (body %v)", body["available"], body)
	}
	if body["reason"] == "" || body["reason"] == nil {
		t.Fatal("reason missing — the operator needs the cause on the panel")
	}
}
