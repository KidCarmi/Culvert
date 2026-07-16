package main

// geoTrackSem tests: trackDestinationCountry spawns one lookup goroutine per
// allowed request, and that lookup can block in uncached DNS resolution for
// the full resolver timeout. The semaphore bounds that fan-out; when
// saturated, the dashboard sample is dropped rather than queued (best-effort
// stats). Both gates — GeoIP enabled and a free tracker slot — run BEFORE the
// spawn, so a disabled or saturated deployment pays no per-request goroutine.

import (
	"testing"
	"time"
)

// swapGeoTrackEnabled stubs the GeoIP-enabled probe (CI loads no .mmdb, so the
// production probe reports disabled) and returns a restore func.
func swapGeoTrackEnabled(t *testing.T, enabled bool) {
	t.Helper()
	old := geoTrackEnabled
	geoTrackEnabled = func() bool { return enabled }
	t.Cleanup(func() { geoTrackEnabled = old })
}

func TestTrackDestinationCountry_DropsWhenSaturated(t *testing.T) {
	// Force the enabled gate open so the test exercises the SEM gate, not the
	// GeoIP-disabled early return.
	swapGeoTrackEnabled(t, true)

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
		// Dropped immediately — no DNS resolution attempted, no queuing, and
		// (new contract) no goroutine spawned for the dropped sample.
	case <-time.After(2 * time.Second):
		t.Fatal("trackDestinationCountry blocked while the tracker pool was saturated; want immediate drop")
	}
}

func TestTrackDestinationCountry_DisabledNeverAcquiresSlot(t *testing.T) {
	swapGeoTrackEnabled(t, false)

	trackDestinationCountry("geo-disabled.example.invalid")

	// The disabled gate returns before the semaphore select and before any
	// spawn, so no tracker slot is ever held — synchronously or later. The
	// short recheck would catch an erroneously spawned goroutine acquiring
	// asynchronously.
	if n := len(geoTrackSem); n != 0 {
		t.Fatalf("tracker slot acquired with GeoIP disabled: len(geoTrackSem)=%d, want 0", n)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(geoTrackSem); n != 0 {
		t.Fatalf("tracker slot acquired asynchronously with GeoIP disabled: len(geoTrackSem)=%d, want 0", n)
	}
}
