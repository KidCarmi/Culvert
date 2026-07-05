package main

// geoTrackSem tests: trackDestinationCountry runs one goroutine per proxied
// request and can block in uncached DNS resolution for the full resolver
// timeout. The semaphore bounds that fan-out; when saturated, the dashboard
// sample is dropped rather than queued (best-effort stats).

import (
	"testing"
	"time"
)

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
