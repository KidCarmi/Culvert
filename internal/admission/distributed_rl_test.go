package admission

import (
	"testing"
	"time"
)

func TestClusterCountStore_FreshCountApply(t *testing.T) {
	cs := &clusterCountStore{counts: map[string]int{}}
	const maxAge = time.Minute

	// Empty store returns 0.
	if got := cs.FreshCount("1.2.3.4", time.Now(), maxAge); got != 0 {
		t.Fatalf("empty store FreshCount = %d, want 0", got)
	}

	// Apply remote counts.
	cs.Apply(map[string]int{"1.2.3.4": 50, "5.6.7.8": 30})
	if got := cs.FreshCount("1.2.3.4", time.Now(), maxAge); got != 50 {
		t.Fatalf("FreshCount(1.2.3.4) = %d, want 50", got)
	}
	if got := cs.FreshCount("5.6.7.8", time.Now(), maxAge); got != 30 {
		t.Fatalf("FreshCount(5.6.7.8) = %d, want 30", got)
	}
	if got := cs.Count(); got != 2 {
		t.Fatalf("Count() = %d, want 2", got)
	}

	// Apply replaces entirely.
	cs.Apply(map[string]int{"9.9.9.9": 10})
	if got := cs.FreshCount("1.2.3.4", time.Now(), maxAge); got != 0 {
		t.Fatal("old key should be gone after Apply")
	}
	if got := cs.Count(); got != 1 {
		t.Fatalf("Count() = %d, want 1", got)
	}

	// CHAOS-61: past maxAge the same broadcast contributes nothing, while
	// Count() still reports what was last received — the two answer different
	// questions and the freshness surface is what separates them.
	if got := cs.FreshCount("9.9.9.9", time.Now().Add(2*maxAge), maxAge); got != 0 {
		t.Fatalf("FreshCount past maxAge = %d, want 0", got)
	}
	if got := cs.Count(); got != 1 {
		t.Fatalf("Count() after expiry = %d, want 1 (the map is not cleared, only ignored)", got)
	}
}

func TestExportHotDeltas_Disabled(t *testing.T) {
	r := NewRateLimiter()
	// Not enabled — should return nil.
	deltas := r.ExportHotDeltas()
	if deltas != nil {
		t.Fatalf("disabled limiter should return nil, got %v", deltas)
	}
}

func TestExportHotDeltas_ThresholdFilter(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(100, time.Minute) // 100 RPM, threshold = 50

	// Add 49 requests for "cold" IP (below 50% threshold).
	for i := 0; i < 49; i++ {
		r.Allow("cold-ip")
	}
	// Add 51 requests for "hot" IP (above 50% threshold).
	for i := 0; i < 51; i++ {
		r.Allow("hot-ip")
	}

	deltas := r.ExportHotDeltas()
	found := false
	for _, d := range deltas {
		if d.IP == "cold-ip" {
			t.Fatal("cold-ip should NOT be exported (below threshold)")
		}
		if d.IP == "hot-ip" {
			found = true
			if d.Count != 51 {
				t.Fatalf("hot-ip count = %d, want 51", d.Count)
			}
		}
	}
	if !found {
		t.Fatal("hot-ip should be in exported deltas")
	}
}

func TestAllowClusterAware_CombinesRemote(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(10, time.Minute)

	// Simulate 7 remote requests from other nodes. The broadcast has to be
	// APPLIED (not just poked into the struct) so it carries a freshness stamp —
	// CHAOS-61 made an unstamped store mean "nothing has ever arrived", which is
	// exactly what a node that never reached its Control Plane should report.
	r.ApplyRemoteCounts(map[string]int{"test-ip": 7})

	// Local: should allow 3 more (7 remote + 3 local = 10 = limit).
	for i := 0; i < 3; i++ {
		if !r.AllowClusterAware("test-ip") {
			t.Fatalf("request %d should be allowed (7 remote + %d local < 10)", i+1, i)
		}
	}
	// 4th should be blocked (7 + 3 = 10 >= 10).
	if r.AllowClusterAware("test-ip") {
		t.Fatal("should be blocked: 7 remote + 3 local >= 10 limit")
	}
}

func TestAllowAuto_Standalone(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(5, time.Minute)

	// A newly constructed limiter starts in standalone mode.
	for i := 0; i < 5; i++ {
		if !r.AllowAuto("standalone-ip") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if r.AllowAuto("standalone-ip") {
		t.Fatal("6th request should be blocked")
	}
}

// ExportHotDeltas historically reports absolute in-window occupancy despite its
// name. Repeated exports must not consume the local admission budget or counts.
func TestExportHotDeltas_RetainsWindowAccounting(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(4, time.Minute)
	for i := 0; i < 3; i++ {
		if !r.Allow("client") {
			t.Fatal("priming")
		}
	}
	for i := 0; i < 2; i++ {
		got := r.ExportHotDeltas()
		if len(got) != 1 || got[0].IP != "client" || got[0].Count != 3 {
			t.Fatalf("export %d: %v", i, got)
		}
	}
	if !r.Allow("client") || r.Allow("client") {
		t.Fatal("export reset local admission accounting")
	}
	r.Configure(4, time.Nanosecond)
	time.Sleep(time.Microsecond)
	if got := r.ExportHotDeltas(); len(got) != 0 {
		t.Fatalf("expired entries exported: %v", got)
	}
}
