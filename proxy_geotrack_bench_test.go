package main

// Benchmarks for the destination-country tracker gating (perf: pre-spawn
// gates). trackDestinationCountry runs once per ALLOWED request from
// handleRequest. Before the gate reorder it was invoked as
// `go trackDestinationCountry(host)`, paying a goroutine spawn per request
// even when GeoIP is disabled (no .mmdb — the common minimal deployment) or
// the tracker pool is saturated; the no-op discovery happened inside the new
// goroutine. The legacy benchmark below reproduces that exact call shape so
// before/after stays measurable in one tree.
//
//	go test -run '^$' -bench 'TrackDestinationCountry' -benchmem .

import (
	"sync"
	"testing"
)

// benchSwapGeoProbe stubs the enabled probe for b's duration.
func benchSwapGeoProbe(b *testing.B, enabled bool) {
	b.Helper()
	old := geoTrackEnabled
	geoTrackEnabled = func() bool { return enabled }
	b.Cleanup(func() { geoTrackEnabled = old })
}

// BenchmarkTrackDestinationCountry_Disabled measures the current per-request
// cost on a GeoIP-disabled deployment: one probe call, no spawn.
func BenchmarkTrackDestinationCountry_Disabled(b *testing.B) {
	benchSwapGeoProbe(b, false)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		trackDestinationCountry("bench.example.invalid")
	}
}

// BenchmarkTrackDestinationCountry_DisabledParallel is the concurrency shape:
// every request goroutine calls the gate; the probe is a single RLock probe
// behind a func var, so parallel callers must not contend.
func BenchmarkTrackDestinationCountry_DisabledParallel(b *testing.B) {
	benchSwapGeoProbe(b, false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			trackDestinationCountry("bench.example.invalid")
		}
	})
}

// BenchmarkTrackDestinationCountry_LegacySpawnDisabled reproduces the
// PRE-change call shape — `go trackDestinationCountry(host)` with the gates
// inside the goroutine — against a disabled probe, so the removed cost is
// measurable next to the new path. A WaitGroup brackets the spawned
// goroutines so the benchmark charges their full lifecycle, not just the
// spawn instruction.
func BenchmarkTrackDestinationCountry_LegacySpawnDisabled(b *testing.B) {
	benchSwapGeoProbe(b, false)
	legacy := func(_ string, wg *sync.WaitGroup) { // host param mirrors the old call shape
		defer wg.Done()
		if !geoTrackEnabled() { // stand-in for the old in-goroutine no-op discovery
			return
		}
		select {
		case geoTrackSem <- struct{}{}:
			<-geoTrackSem
		default:
		}
	}
	var wg sync.WaitGroup
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go legacy("bench.example.invalid", &wg)
	}
	wg.Wait()
}

// BenchmarkTrackDestinationCountry_Saturated measures the saturated-pool drop
// (enabled probe, no free slot): a channel select, still no spawn.
func BenchmarkTrackDestinationCountry_Saturated(b *testing.B) {
	benchSwapGeoProbe(b, true)
	for i := 0; i < cap(geoTrackSem); i++ {
		geoTrackSem <- struct{}{}
	}
	b.Cleanup(func() {
		for i := 0; i < cap(geoTrackSem); i++ {
			<-geoTrackSem
		}
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		trackDestinationCountry("bench.example.invalid")
	}
}
