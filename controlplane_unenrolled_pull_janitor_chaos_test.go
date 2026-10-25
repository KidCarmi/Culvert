package main

// controlplane_unenrolled_pull_janitor_chaos_test.go — CHAOS-90: the unenrolled
// config-pull throttle must not grow without bound.
//
// unenrolledConfigPullAllow prunes a per-IP timestamp slice only on that same
// IP's NEXT pull, so an address that pulls once and never returns left a
// permanent map entry. Its twin, enrollRateLimit, has had a periodic sweep for
// exactly this since the hazard was recognised — its own comment names it — and
// the sweep was never carried across. On a control plane the gRPC port is
// reachable by any routable peer, so one request per source address was enough
// to grow the map for the process lifetime.

import (
	"fmt"
	"testing"
	"time"
)

// resetUnenrolledPullForTest empties the throttle map and restores it after the
// test. The map is a process global shared with controlplane_exfil_ratelimit_test.go,
// so leaving entries behind would leak into whatever runs next.
func resetUnenrolledPullForTest(t *testing.T) {
	t.Helper()
	unenrolledConfigPull.mu.Lock()
	prev := unenrolledConfigPull.attempts
	unenrolledConfigPull.attempts = map[string][]time.Time{}
	unenrolledConfigPull.mu.Unlock()
	t.Cleanup(func() {
		unenrolledConfigPull.mu.Lock()
		unenrolledConfigPull.attempts = prev
		unenrolledConfigPull.mu.Unlock()
	})
}

func unenrolledPullEntries() int {
	unenrolledConfigPull.mu.Lock()
	defer unenrolledConfigPull.mu.Unlock()
	return len(unenrolledConfigPull.attempts)
}

// TestChaos90_JanitorReclaimsOneShotPeerEntries is the regression test: a sweep
// of peers that pulled once, long enough ago to have aged out, must leave the
// map empty rather than holding one entry per address forever.
func TestChaos90_JanitorReclaimsOneShotPeerEntries(t *testing.T) {
	resetUnenrolledPullForTest(t)

	// A source sweep: many distinct addresses, one pull each, all stale. The
	// /32 documentation prefix has far more addresses than an attacker needs;
	// 500 is simply enough to make a surviving entry obvious.
	const peers = 500
	stale := time.Now().Add(-2 * unenrolledConfigPullWindow)
	unenrolledConfigPull.mu.Lock()
	for i := 0; i < peers; i++ {
		unenrolledConfigPull.attempts[fmt.Sprintf("2001:db8::%x", i)] = []time.Time{stale}
	}
	unenrolledConfigPull.mu.Unlock()

	if got := unenrolledPullEntries(); got != peers {
		t.Fatalf("setup: %d entries, want %d", got, peers)
	}
	unenrolledConfigPullCleanup()
	if got := unenrolledPullEntries(); got != 0 {
		t.Errorf("%d entries survived the sweep, want 0 — the map still grows once per distinct peer address for the process lifetime", got)
	}
}

// TestChaos90_JanitorKeepsLiveWindows is the negative control. A sweep that
// reclaimed in-window state would silently reset the throttle, turning a
// memory fix into an exfiltration-rate regression — the throttle exists to
// make bulk pulls slow.
func TestChaos90_JanitorKeepsLiveWindows(t *testing.T) {
	resetUnenrolledPullForTest(t)

	const ip = "203.0.113.77"
	now := time.Now()
	unenrolledConfigPull.mu.Lock()
	unenrolledConfigPull.attempts[ip] = []time.Time{
		now.Add(-2 * unenrolledConfigPullWindow), // stale: must be dropped
		now.Add(-time.Second),                    // live: must be kept
	}
	// A second peer, entirely stale.
	unenrolledConfigPull.attempts["203.0.113.78"] = []time.Time{now.Add(-time.Hour)}
	unenrolledConfigPull.mu.Unlock()

	unenrolledConfigPullCleanup()

	unenrolledConfigPull.mu.Lock()
	kept := len(unenrolledConfigPull.attempts[ip])
	_, otherPresent := unenrolledConfigPull.attempts["203.0.113.78"]
	unenrolledConfigPull.mu.Unlock()

	if kept != 1 {
		t.Errorf("live peer kept %d timestamps, want 1 (the stale one dropped, the in-window one retained)", kept)
	}
	if otherPresent {
		t.Error("the fully stale peer was not reclaimed")
	}
}

// TestChaos90_JanitorDoesNotChangeTheThrottleDecision pins the property that
// makes this fix safe to ship: sweeping is about reclaiming memory, not about
// relaxing the limit. A peer that has exhausted its window must still be
// refused immediately after a sweep.
func TestChaos90_JanitorDoesNotChangeTheThrottleDecision(t *testing.T) {
	resetUnenrolledPullForTest(t)

	const ip = "203.0.113.90"
	// Exhaust the window.
	for i := 0; ; i++ {
		if !unenrolledConfigPullAllow(ip) {
			break
		}
		if i > 1000 {
			t.Fatal("the throttle never refused a pull — the limit is not being enforced")
		}
	}
	unenrolledConfigPullCleanup()
	if unenrolledConfigPullAllow(ip) {
		t.Error("a sweep re-admitted an exhausted peer — the memory fix has relaxed the exfiltration throttle")
	}
	// And a fresh peer is still admitted.
	if !unenrolledConfigPullAllow("203.0.113.91") {
		t.Error("a previously unseen peer was refused")
	}
}
