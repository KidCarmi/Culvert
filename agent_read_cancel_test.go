package main

// agent_read_cancel_test.go — the shared maintenance-agent reads (status and
// backup listing) are single-flighted and cached for every viewer, so one
// viewer's disconnect must never be published as "agent unavailable" (ASTRA
// review of f37a2a39: with b579 a cancelled request poisoned the status for
// 15 s). An unavailable read is reused only briefly, so recovery is reported
// within seconds; single-flight still bounds the host to one read at a time.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedAgent answers /v1/status and /v1/backups only after release is closed,
// and reports when a request has arrived.
func gatedAgent(t *testing.T, healthy *atomic.Bool) (srv *httptest.Server, arrived chan struct{}, release chan struct{}, hits *atomic.Int64) {
	t.Helper()
	arrived, release, hits = make(chan struct{}, 16), make(chan struct{}), &atomic.Int64{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		arrived <- struct{}{}
		<-release
		if !healthy.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/v1/backups" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"agent_version":"v9","privilege_mode":"sudo_scoped","compose_stack_up":true}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv(envMaintAgentURL, srv.URL)
	return srv, arrived, release, hits
}

var agentReads = []struct {
	name  string
	reset func(*testing.T)
	read  func(context.Context) map[string]any
	age   func(time.Duration)
}{
	{"status", resetMaintAgentStatusCache, maintAgentStatusPayload, func(d time.Duration) {
		maintAgentStatusCache.mu.Lock()
		maintAgentStatusCache.at = maintAgentStatusCache.at.Add(-d)
		maintAgentStatusCache.mu.Unlock()
	}},
	{"backups", resetBackupsCache, backupsListingPayload, func(d time.Duration) {
		backupsCache.mu.Lock()
		backupsCache.at = backupsCache.at.Add(-d)
		backupsCache.mu.Unlock()
	}},
}

func TestAgentRead_CancelledRequesterDoesNotPoisonTheSharedResult(t *testing.T) {
	for _, tc := range agentReads {
		t.Run(tc.name, func(t *testing.T) {
			tc.reset(t)
			var healthy atomic.Bool
			healthy.Store(true)
			_, arrived, release, hits := gatedAgent(t, &healthy)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan map[string]any, 1)
			go func() { done <- tc.read(ctx) }()
			<-arrived
			cancel() // the viewer goes away while the shared read is in flight
			time.Sleep(50 * time.Millisecond)
			close(release)
			<-done

			got := tc.read(context.Background())
			if got["available"] != true {
				t.Fatalf("after one viewer cancelled, the next viewer got %v (the cancellation was cached as agent health)", got)
			}
			if n := hits.Load(); n != 1 {
				t.Fatalf("the agent was read %d times; the in-flight read should have been reused", n)
			}
		})
	}
}

func TestAgentRead_FollowersShareOneRead(t *testing.T) {
	for _, tc := range agentReads {
		t.Run(tc.name, func(t *testing.T) {
			tc.reset(t)
			var healthy atomic.Bool
			healthy.Store(true)
			_, arrived, release, hits := gatedAgent(t, &healthy)
			var wg sync.WaitGroup
			results := make([]map[string]any, 5)
			for i := range results {
				wg.Add(1)
				go func(i int) { defer wg.Done(); results[i] = tc.read(context.Background()) }(i)
			}
			<-arrived
			time.Sleep(50 * time.Millisecond)
			close(release)
			wg.Wait()
			if n := hits.Load(); n != 1 {
				t.Fatalf("%d concurrent viewers caused %d agent reads; single-flight must keep it to one", len(results), n)
			}
			for i, r := range results {
				if r["available"] != true {
					t.Fatalf("viewer %d got %v", i, r)
				}
			}
		})
	}
}

func TestAgentRead_UnavailableIsReusedBrieflyAndRecovers(t *testing.T) {
	for _, tc := range agentReads {
		t.Run(tc.name, func(t *testing.T) {
			tc.reset(t)
			var healthy atomic.Bool // agent down first
			_, _, release, hits := gatedAgent(t, &healthy)
			close(release)
			if got := tc.read(context.Background()); got["available"] != false {
				t.Fatalf("down agent reported %v", got)
			}
			healthy.Store(true)
			// Inside the failure window: reused (bounded load on a down agent).
			if got := tc.read(context.Background()); got["available"] != false || hits.Load() != 1 {
				t.Fatalf("within %s the failure must be reused without a new read: %v, %d reads", agentReadFailureTTL, got, hits.Load())
			}
			// Past the short failure window — still far inside the 15 s TTL.
			tc.age(agentReadFailureTTL + time.Second)
			if got := tc.read(context.Background()); got["available"] != true || hits.Load() != 2 {
				t.Fatalf("a recovered agent was not re-read after %s: %v, %d reads", agentReadFailureTTL, got, hits.Load())
			}
			// A healthy result keeps the full TTL.
			tc.age(agentReadFailureTTL + time.Second)
			tc.read(context.Background())
			if hits.Load() != 2 {
				t.Fatalf("a healthy result was re-read before its TTL (%d reads)", hits.Load())
			}
		})
	}
}
