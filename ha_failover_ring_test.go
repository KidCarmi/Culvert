package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// TestHAFailoverRing_RecordEvictOrder covers the bounded ring: newest-first
// ordering, and eviction of the oldest once past the cap.
func TestHAFailoverRing_RecordEvictOrder(t *testing.T) {
	r := &haFailoverRing{}
	base := time.Unix(1_700_000_000, 0).UTC()

	// Fill past capacity so the oldest entries are evicted.
	total := haFailoverMaxEvents + 5
	for i := 0; i < total; i++ {
		to := "leader"
		from := "standby"
		if i%2 == 1 {
			to, from = "standby", "leader"
		}
		r.record(from, to, "reason-"+strconv.Itoa(i), int64(i), base.Add(time.Duration(i)*time.Second))
	}

	got := r.list()
	if len(got) != haFailoverMaxEvents {
		t.Fatalf("ring size = %d, want cap %d", len(got), haFailoverMaxEvents)
	}
	// Newest first: the last recorded epoch (total-1) is at index 0.
	if got[0].Epoch != int64(total-1) {
		t.Errorf("newest event epoch = %d, want %d", got[0].Epoch, total-1)
	}
	// Oldest surviving entry is total-cap (the first `5` were evicted).
	if got[len(got)-1].Epoch != int64(total-haFailoverMaxEvents) {
		t.Errorf("oldest surviving epoch = %d, want %d", got[len(got)-1].Epoch, total-haFailoverMaxEvents)
	}
	// Descending epoch order throughout.
	for i := 1; i < len(got); i++ {
		if got[i-1].Epoch <= got[i].Epoch {
			t.Fatalf("not newest-first at %d: %d <= %d", i, got[i-1].Epoch, got[i].Epoch)
		}
	}
}

// TestHAFailoverRing_BoundsReason pins the reason length bound (a flap loop with
// verbose lease errors must not balloon a row).
func TestHAFailoverRing_BoundsReason(t *testing.T) {
	r := &haFailoverRing{}
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'x'
	}
	r.record("leader", "standby", string(long), 1, time.Unix(1_700_000_000, 0).UTC())
	got := r.list()
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if len(got[0].Reason) > 300 { // boundedErr caps at 256 (+ ellipsis)
		t.Errorf("reason not bounded: len=%d", len(got[0].Reason))
	}
}

// TestHAFailoverRing_Concurrent exercises the mutex under -race: concurrent
// writers and readers must not data-race.
func TestHAFailoverRing_Concurrent(t *testing.T) {
	r := &haFailoverRing{}
	base := time.Unix(1_700_000_000, 0).UTC()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				r.record("standby", "leader", "r", int64(i), base)
				_ = r.list()
			}
		}(w)
	}
	wg.Wait()
	if len(r.list()) != haFailoverMaxEvents {
		t.Fatalf("after concurrent writes, ring = %d, want cap %d", len(r.list()), haFailoverMaxEvents)
	}
}

// TestHAFailoverRing_ProducerWiring verifies promote() and selfFence() actually
// append to the ring — the end-to-end wiring, driven through the real HA lease
// paths with halease.Fake. Swaps the global ring for isolation.
func TestHAFailoverRing_ProducerWiring(t *testing.T) {
	tempHADir(t)
	defer haFailoverRingSwapForTest()()

	f := halease.NewFake(200 * time.Millisecond)
	h := leaseStandby(f, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	evs := globalHAFailoverRing.Load().list()
	if len(evs) != 1 || evs[0].FromRole != "standby" || evs[0].ToRole != "leader" {
		t.Fatalf("promotion not recorded: %+v", evs)
	}

	// Steal the lease so the keepalive self-fences.
	f.ExpireForTest()
	if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
		t.Fatal("usurper acquire")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && h.IsLeader() {
		time.Sleep(20 * time.Millisecond)
	}
	if h.IsLeader() {
		t.Fatal("leader did not self-fence")
	}
	// Newest-first: the self-fence (leader→standby) is now on top.
	evs = globalHAFailoverRing.Load().list()
	if len(evs) < 2 || evs[0].FromRole != "leader" || evs[0].ToRole != "standby" {
		t.Fatalf("self-fence not recorded on top: %+v", evs)
	}
}

// TestAPIClusterHA_ExposesFailoverEvents pins that the GET response carries the
// failover_events array from the ring.
func TestAPIClusterHA_ExposesFailoverEvents(t *testing.T) {
	defer haFailoverRingSwapForTest()()
	globalHAFailoverRing.Load().record("standby", "leader", "manual promotion", 9, time.Unix(1_700_000_000, 0).UTC())

	rec := httptest.NewRecorder()
	apiClusterHA(rec, roleReq(RoleViewer, http.MethodGet, "/api/cluster/ha", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET code=%d want 200", rec.Code)
	}
	var resp struct {
		FailoverEvents []haFailoverEvent `json:"failover_events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.FailoverEvents) != 1 || resp.FailoverEvents[0].ToRole != "leader" || resp.FailoverEvents[0].Epoch != 9 {
		t.Fatalf("failover_events not surfaced: %+v", resp.FailoverEvents)
	}
}
