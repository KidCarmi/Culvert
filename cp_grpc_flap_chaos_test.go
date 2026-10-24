package main

// cp_grpc_flap_chaos_test.go — CHAOS-71: flap damping for the CP listener's
// failure episode (Codex P1 4297020933 on #1556). A bind no longer ends the
// episode; only a serve that lasts cpGRPCServeStableAfter does.

import (
	"testing"
	"time"
)

// cpFlapClock puts the listener plane on a controllable clock.
func cpFlapClock(t *testing.T) (advance func(time.Duration)) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	prev := cpGRPCHealthNow
	cpGRPCHealthNow = func() time.Time { return now }
	t.Cleanup(func() { cpGRPCHealthNow = prev })
	return func(d time.Duration) { now = now.Add(d) }
}

// TestChaos71_FlappingListenerAccumulatesOneEpisode drives the supervisor's
// exact recorder sequence for a listener whose Serve dies right after every
// bind (bind → noteCPGRPCBound, serve ends → noteCPGRPCServeEnded, back off),
// on an injected clock. The cycles must form ONE episode that crosses the
// 30 s threshold, pages ONCE and withholds the fencing lease; a bind that then
// stays up past the stability window must end it.
func TestChaos71_FlappingListenerAccumulatesOneEpisode(t *testing.T) {
	alerts := cpChaosSetup(t)
	advance := cpFlapClock(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	const backoff = 5 * time.Second
	noteCPGRPCListenFailure("port_in_use", backoff, cpGRPCHealthNow()) // the outage begins
	cpGRPCListener.mu.Lock()
	episode := cpGRPCListener.episode
	cpGRPCListener.mu.Unlock()

	cycles := 0
	for elapsed := time.Duration(0); elapsed <= cpGRPCUnavailableAfter+backoff; elapsed += backoff {
		advance(backoff)
		if _, rebound := noteCPGRPCBound(); !rebound {
			t.Fatalf("cycle %d: the bind was not reported as inside the open episode", cycles)
		}
		if snap := cpGRPCListenerState(); !snap.Stabilizing || snap.Unavailable {
			t.Fatalf("cycle %d right after the bind: stabilizing=%v unavailable=%v", cycles, snap.Stabilizing, snap.Unavailable)
		}
		noteCPGRPCServeEnded("listen_failed", backoff) // Serve died at once
		cycles++
	}

	snap := cpGRPCListenerState()
	cpGRPCListener.mu.Lock()
	sameEpisode := cpGRPCListener.episode == episode
	cpGRPCListener.mu.Unlock()
	if !sameEpisode {
		t.Fatal("a bind followed by an immediate serve failure started a NEW episode — the threshold can never accumulate")
	}
	if !snap.Unavailable || snap.FailingFor < cpGRPCUnavailableAfter {
		t.Fatalf("after %d flap cycles: unavailable=%v failingFor=%s — the flap must cross the %s threshold",
			cycles, snap.Unavailable, snap.FailingFor, cpGRPCUnavailableAfter)
	}
	if int(snap.Consecutive) != cycles+1 {
		t.Errorf("consecutive = %d, want %d (one per failure in the episode)", snap.Consecutive, cycles+1)
	}
	if got := len(alerts()); got != 1 {
		t.Errorf("the flapping episode paged %d time(s), want exactly 1", got)
	}
	if _, withhold := cpGRPCLeaseRenewWithheld(); !withhold {
		t.Error("a lease-mode leader whose listener flaps past the threshold keeps renewing — the standby can never take over")
	}

	// A bind that stays up for the stability window ends the episode.
	noteCPGRPCBound()
	advance(cpGRPCServeStableAfter - time.Second)
	if snap := cpGRPCListenerState(); !snap.Stabilizing {
		t.Fatal("the episode closed before the serve had lasted the stability window")
	}
	advance(time.Second)
	snap = cpGRPCListenerState()
	if snap.Stabilizing || snap.Consecutive != 0 || snap.Unavailable {
		t.Fatalf("after a stable serve: stabilizing=%v consecutive=%d unavailable=%v, want a closed episode",
			snap.Stabilizing, snap.Consecutive, snap.Unavailable)
	}
	if _, withhold := cpGRPCLeaseRenewWithheld(); withhold {
		t.Error("the lease is still withheld after a stable serve")
	}

	// The next failure is a NEW episode, which may page again.
	noteCPGRPCListenFailure("port_in_use", backoff, cpGRPCHealthNow())
	cpGRPCListener.mu.Lock()
	next := cpGRPCListener.episode
	cpGRPCListener.mu.Unlock()
	if next != episode+1 {
		t.Errorf("episode after a stable serve then a failure = %d, want %d", next, episode+1)
	}
}

// TestChaos71_FailureAfterAStableServeStartsANewEpisode: the failure recorder
// itself closes an episode whose serve outlived the stability window — no
// reader has to observe the state in between — so the next failure opens a
// fresh episode with a fresh alert latch and threshold.
func TestChaos71_FailureAfterAStableServeStartsANewEpisode(t *testing.T) {
	cpChaosSetup(t)
	advance := cpFlapClock(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCListenFailure("port_in_use", time.Second, cpGRPCHealthNow())
	cpGRPCListener.mu.Lock()
	first := cpGRPCListener.episode
	cpGRPCListener.mu.Unlock()

	noteCPGRPCBound()
	advance(cpGRPCServeStableAfter) // served for the whole window; nobody reads the state
	noteCPGRPCServeEnded("listen_failed", time.Second)

	cpGRPCListener.mu.Lock()
	ep, consecutive, alerted := cpGRPCListener.episode, cpGRPCListener.consecutive, cpGRPCListener.alerted
	cpGRPCListener.mu.Unlock()
	if ep != first+1 || consecutive != 1 || alerted {
		t.Errorf("after a stable serve then a failure: episode=%d (want %d) consecutive=%d (want 1) alerted=%v (want false)",
			ep, first+1, consecutive, alerted)
	}
}
