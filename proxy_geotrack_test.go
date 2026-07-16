package main

// geoTrackSem tests: trackDestinationCountry runs one goroutine per proxied
// request and can block in uncached DNS resolution for the full resolver
// timeout. The semaphore bounds that fan-out; when saturated, the dashboard
// sample is dropped rather than queued (best-effort stats).

import (
	"testing"
	"time"
)

// TestMaybeTrackDestinationCountry_DisabledSkipsSpawn pins the disabled-path
// contract of the dispatch gate: with no GeoIP DB loaded the tracker goroutine
// is never spawned (the pre-gate code spawned one per allowed request just to
// discover geoip.Enabled() == false inside geo.LookupFull). The allocation
// half of the contract is gated by TestBenchGate_GeoTrackDispatchDisabledAllocs.
func TestMaybeTrackDestinationCountry_DisabledSkipsSpawn(t *testing.T) {
	orig := geoTrackEnabledFn
	geoTrackEnabledFn = func() bool { return false }
	defer func() { geoTrackEnabledFn = orig }()

	if maybeTrackDestinationCountry("chaos-example.invalid") {
		t.Fatal("maybeTrackDestinationCountry spawned a tracker with GeoIP disabled; want no-op")
	}
}

// TestMaybeTrackDestinationCountry_EnabledSpawns pins the enabled-path
// contract: the gate is a pure hoist of the Enabled() probe, so an enabled
// deployment must spawn the tracker exactly as the pre-gate code did. The
// seam stubs only the probe (no .mmdb fixture exists in the tree); the spawned
// tracker re-checks the real geoip.Enabled() inside geo.LookupFull and exits
// without recording — the benign probe/spawn race documented on the gate.
func TestMaybeTrackDestinationCountry_EnabledSpawns(t *testing.T) {
	orig := geoTrackEnabledFn
	geoTrackEnabledFn = func() bool { return true }
	defer func() { geoTrackEnabledFn = orig }()

	if !maybeTrackDestinationCountry("chaos-example.invalid") {
		t.Fatal("maybeTrackDestinationCountry skipped the tracker with GeoIP enabled; want spawn")
	}
}

func TestTrackDestinationCountry_DropsWhenSaturated(t *testing.T) {
	// Saturate the tracker pool.
	for i := 0; i < cap(geoTrackSem); i++ {
		geoTrackSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(geoTrackSem); i++ {
			<-geoTrackSem
		}
	}()

	done := make(chan struct{})
	go func() {
		trackDestinationCountry("chaos-example.invalid")
		close(done)
	}()

	select {
	case <-done:
		// Dropped immediately — no DNS resolution attempted, no queuing.
	case <-time.After(2 * time.Second):
		t.Fatal("trackDestinationCountry blocked while the tracker pool was saturated; want immediate drop")
	}
}
