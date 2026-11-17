package scanexcl

// scanexcl_bench_test.go — the measurement behind the scan-exclusion read path.
//
// IsHostExcluded runs once per inspected tunnel response (proxy_tunnel.go
// scanInspectBody, UNCONDITIONALLY, ahead of the content-type gate) and once
// per plain-HTTP response whenever any body scanner is enabled
// (proxy_http.go scanHTTPResponseBody). IsHashExcluded runs once per body
// scan (internal/secscan). All three are reads of a map that changes only
// when an admin edits the lists.
//
// legacyStore is a VERBATIM copy of the RWMutex implementation this package
// shipped before the published-view change, kept in-tree for the same reason
// legacyRemoveHopHeaders and BenchmarkAddLegacyGate are: the before/after
// comparison has to stay reproducible on hardware other than the box the
// numbers below were taken on. It keeps its OWN state, so no arm can perturb
// the shipped Store, and TestLegacyStore_MatchesShipped proves the two agree
// on every decision — so the comparison rests on cost, not on a broken
// prototype. It must not be "kept in sync" with Store; its value is that it
// does not move.
//
// Read the PARALLEL arms as the finding. All arms are RunParallel, so ns/op is
// wall time per op across all workers: a genuinely parallel read FALLS as
// cores are added and one that serialises on a shared word rises.

import (
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// ── legacy arm: the shipped pre-change implementation, verbatim ──────────────

type legacyStore struct {
	mu     sync.RWMutex
	hashes map[string]bool
	hosts  map[string]bool
}

func newLegacyStore() *legacyStore {
	return &legacyStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
}

func (s *legacyStore) replace(hashes, hosts []string) {
	hmap := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			hmap[h] = true
		}
	}
	hostMap := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = hostutil.StripHostPort(strings.TrimSpace(strings.ToLower(h)))
		if h != "" {
			hostMap[h] = true
		}
	}
	s.mu.Lock()
	s.hashes = hmap
	s.hosts = hostMap
	s.mu.Unlock()
}

func (s *legacyStore) isHashExcluded(hash string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hashes[strings.ToLower(hash)]
}

func (s *legacyStore) isHostExcluded(host string) bool {
	if s == nil || host == "" {
		return false
	}
	host = hostutil.StripHostPort(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hosts[strings.ToLower(host)]
}

// ── corpora ─────────────────────────────────────────────────────────────────

// benchHosts is the rotating destination working set. A gateway serves a wide
// set of destinations, so a benchmark that re-probes ONE host measures a hot
// cache line the product never has.
var benchHosts = []string{
	"www.example.com", "cdn.example.net", "api.example.org",
	"mirror.internal.example", "updates.example.io", "telemetry.example.co",
	"images.example.com:443", "assets.example.net",
}

// benchExcludedHosts is what an admin actually configures: a handful of
// known-good internal mirrors.
var benchExcludedHosts = []string{
	"mirror.internal.example", "artifacts.internal.example",
	"packages.internal.example",
}

const benchHash = "3b1f2c0d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e"

func configuredStore() *Store {
	s := New()
	s.Replace([]string{benchHash}, benchExcludedHosts)
	return s
}

func configuredLegacy() *legacyStore {
	s := newLegacyStore()
	s.replace([]string{benchHash}, benchExcludedHosts)
	return s
}

// ── host path: default posture (no exclusions configured) ───────────────────

func BenchmarkIsHostExcluded_EmptyLegacy(b *testing.B) {
	s := newLegacyStore()
	benchHostSerial(b, func(h string) bool { return s.isHostExcluded(h) })
}

func BenchmarkIsHostExcluded_Empty(b *testing.B) {
	s := New()
	benchHostSerial(b, s.IsHostExcluded)
}

func BenchmarkIsHostExcluded_EmptyLegacyParallel(b *testing.B) {
	s := newLegacyStore()
	benchHostParallel(b, func(h string) bool { return s.isHostExcluded(h) })
}

func BenchmarkIsHostExcluded_EmptyParallel(b *testing.B) {
	s := New()
	benchHostParallel(b, s.IsHostExcluded)
}

// ── host path: exclusions configured, destination not on the list ───────────

func BenchmarkIsHostExcluded_MissLegacy(b *testing.B) {
	s := configuredLegacy()
	benchHostSerial(b, func(h string) bool { return s.isHostExcluded(h) })
}

func BenchmarkIsHostExcluded_Miss(b *testing.B) {
	s := configuredStore()
	benchHostSerial(b, s.IsHostExcluded)
}

func BenchmarkIsHostExcluded_MissLegacyParallel(b *testing.B) {
	s := configuredLegacy()
	benchHostParallel(b, func(h string) bool { return s.isHostExcluded(h) })
}

func BenchmarkIsHostExcluded_MissParallel(b *testing.B) {
	s := configuredStore()
	benchHostParallel(b, s.IsHostExcluded)
}

// ── host path: the configured host actually matches ─────────────────────────

func BenchmarkIsHostExcluded_HitLegacy(b *testing.B) {
	s := configuredLegacy()
	benchOneHostSerial(b, benchExcludedHosts[0], func(h string) bool { return s.isHostExcluded(h) })
}

func BenchmarkIsHostExcluded_Hit(b *testing.B) {
	s := configuredStore()
	benchOneHostSerial(b, benchExcludedHosts[0], s.IsHostExcluded)
}

// ── hash path: once per body scan ───────────────────────────────────────────

func BenchmarkIsHashExcluded_EmptyLegacy(b *testing.B) {
	s := newLegacyStore()
	benchOneHostSerial(b, benchHash, func(h string) bool { return s.isHashExcluded(h) })
}

func BenchmarkIsHashExcluded_Empty(b *testing.B) {
	s := New()
	benchOneHostSerial(b, benchHash, s.IsHashExcluded)
}

func BenchmarkIsHashExcluded_EmptyLegacyParallel(b *testing.B) {
	s := newLegacyStore()
	benchOneHostParallel(b, benchHash, func(h string) bool { return s.isHashExcluded(h) })
}

func BenchmarkIsHashExcluded_EmptyParallel(b *testing.B) {
	s := New()
	benchOneHostParallel(b, benchHash, s.IsHashExcluded)
}

func BenchmarkIsHashExcluded_HitLegacy(b *testing.B) {
	s := configuredLegacy()
	benchOneHostSerial(b, benchHash, func(h string) bool { return s.isHashExcluded(h) })
}

func BenchmarkIsHashExcluded_Hit(b *testing.B) {
	s := configuredStore()
	benchOneHostSerial(b, benchHash, s.IsHashExcluded)
}

// ── drivers ─────────────────────────────────────────────────────────────────

var benchSink bool

func benchHostSerial(b *testing.B, f func(string) bool) {
	b.ReportAllocs()
	b.ResetTimer()
	var sink bool
	for i := 0; i < b.N; i++ {
		sink = f(benchHosts[i%len(benchHosts)])
	}
	benchSink = sink
}

func benchOneHostSerial(b *testing.B, v string, f func(string) bool) {
	b.ReportAllocs()
	b.ResetTimer()
	var sink bool
	for i := 0; i < b.N; i++ {
		sink = f(v)
	}
	benchSink = sink
}

func benchHostParallel(b *testing.B, f func(string) bool) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		var sink bool
		for pb.Next() {
			sink = f(benchHosts[i%len(benchHosts)])
			i++
		}
		// Worker-local: a shared sink written by every worker is itself a
		// data race (fails -race) and a shared write in a benchmark that
		// measures the absence of one.
		runtime.KeepAlive(sink)
	})
}

func benchOneHostParallel(b *testing.B, v string, f func(string) bool) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			sink = f(v)
		}
		runtime.KeepAlive(sink) // worker-local; see benchHostParallel
	})
}
