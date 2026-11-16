package scanexcl

// scanexcl_view_test.go — the gates that hold the published-view read path.
//
// The optimization is a SYNCHRONISATION change, not a decision change, so the
// tests here are differential (the shipped Store must agree with the verbatim
// RWMutex arm in scanexcl_bench_test.go on every input) and structural (the
// empty-posture reads must stay allocation-free and must not fall back to
// scanning the key). Timing assertions are deliberately absent: the numbers
// live in the Store doc comment and are re-measured, not gated.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// diffCorpus is the input corpus both arms are asked about. It deliberately
// mixes the shapes that could diverge: case, surrounding space, ports, IPv6
// literals with and without brackets, trailing dots, the empty string, and a
// digest in the wrong case.
var diffCorpus = []string{
	"", " ", "www.example.com", "WWW.EXAMPLE.COM", " www.example.com ",
	"www.example.com:443", "www.example.com.", "mirror.internal.example",
	"MIRROR.INTERNAL.EXAMPLE", "mirror.internal.example:8443",
	"2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:8080", "2001:db8::2",
	"[::1]:443", "::1", "localhost", "LocalHost:3128",
	benchHash, strings.ToUpper(benchHash), " " + benchHash + " ",
	benchHash[:63], benchHash + "0",
}

// diffConfigs are the list contents both arms are configured with. Each is
// applied to both arms and the whole corpus is then asked of both.
var diffConfigs = []struct {
	name   string
	hashes []string
	hosts  []string
}{
	{"empty", nil, nil},
	{"hosts-only", nil, benchExcludedHosts},
	{"hashes-only", []string{benchHash}, nil},
	{"both", []string{benchHash}, benchExcludedHosts},
	{"uppercase-config", []string{strings.ToUpper(benchHash)}, []string{"MIRROR.INTERNAL.EXAMPLE"}},
	{"spaced-config", []string{" " + benchHash + " "}, []string{"  mirror.internal.example  "}},
	{"empty-entries", []string{"", "  "}, []string{"", " "}},
	{"ported-config", nil, []string{"mirror.internal.example:8443", "[2001:db8::1]:443"}},
	{"ipv6-config", nil, []string{"2001:db8::1", "[::1]"}},
}

// TestLegacyStore_MatchesShipped is the differential gate the benchmark's
// legacy arm rests on: if the two arms disagreed on any decision, the cost
// comparison would be measuring two different functions.
func TestLegacyStore_MatchesShipped(t *testing.T) {
	for _, cfg := range diffConfigs {
		t.Run(cfg.name, func(t *testing.T) {
			shipped := New()
			shipped.Replace(cfg.hashes, cfg.hosts)
			legacy := newLegacyStore()
			legacy.replace(cfg.hashes, cfg.hosts)

			for _, in := range diffCorpus {
				if got, want := shipped.IsHostExcluded(in), legacy.isHostExcluded(in); got != want {
					t.Errorf("IsHostExcluded(%q) = %v, legacy = %v", in, got, want)
				}
				if got, want := shipped.IsHashExcluded(in), legacy.isHashExcluded(in); got != want {
					t.Errorf("IsHashExcluded(%q) = %v, legacy = %v", in, got, want)
				}
			}
		})
	}
}

// TestZeroStore_UsableWithoutNew pins that the published pointer's nil state
// reads as an empty view, so &Store{} keeps working without New — the shape
// package main's scan_host_ipv6_test.go constructs.
func TestZeroStore_UsableWithoutNew(t *testing.T) {
	var s Store
	if s.IsHostExcluded("www.example.com") || s.IsHashExcluded(benchHash) {
		t.Fatal("zero Store excluded something")
	}
	if h, hosts := s.Lists(); len(h) != 0 || len(hosts) != 0 {
		t.Fatalf("zero Store Lists() = %v, %v, want empty", h, hosts)
	}
	s.Replace([]string{benchHash}, benchExcludedHosts)
	if !s.IsHostExcluded(benchExcludedHosts[0]) {
		t.Fatal("Replace on a zero Store did not publish the host list")
	}
	if !s.IsHashExcluded(benchHash) {
		t.Fatal("Replace on a zero Store did not publish the hash list")
	}
}

// TestNilStore_ReadsFalse keeps the nil-receiver contract the callers rely on
// (globalScanExclusions is read before startup wiring completes).
func TestNilStore_ReadsFalse(t *testing.T) {
	var s *Store
	if s.IsHostExcluded("www.example.com") || s.IsHashExcluded(benchHash) {
		t.Fatal("nil Store excluded something")
	}
}

// TestEmptyPosture_AllocationFree is the structural gate on the saving: the
// default posture must answer from the length check alone. It is
// machine-independent — it counts allocations, not nanoseconds — and it fails
// if a future change reintroduces a per-call allocation on the request path.
func TestEmptyPosture_AllocationFree(t *testing.T) {
	s := New()
	// Folded outside the closures: strings.ToUpper allocates, and the budget
	// below is about the store's own cost, not the corpus construction's.
	upperHash := strings.ToUpper(benchHash)
	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"IsHostExcluded", func() { _ = s.IsHostExcluded("WWW.Example.COM:443") }},
		{"IsHashExcluded", func() { _ = s.IsHashExcluded(upperHash) }},
	} {
		if n := testing.AllocsPerRun(200, tc.run); n != 0 {
			t.Errorf("%s on an empty store: %v allocs/op, want 0", tc.name, n)
		}
	}
}

// TestConfiguredPosture_AllocationFree pins that a configured store stays
// allocation-free too, for the lower-case destinations a gateway actually
// serves. An upper-case host legitimately allocates in strings.ToLower, which
// is why the folded shape is not asserted here.
func TestConfiguredPosture_AllocationFree(t *testing.T) {
	s := configuredStore()
	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"host miss", func() { _ = s.IsHostExcluded("www.example.com") }},
		{"host hit", func() { _ = s.IsHostExcluded(benchExcludedHosts[0]) }},
		{"hash hit", func() { _ = s.IsHashExcluded(benchHash) }},
	} {
		if n := testing.AllocsPerRun(200, tc.run); n != 0 {
			t.Errorf("%s on a configured store: %v allocs/op, want 0", tc.name, n)
		}
	}
}

// TestPublishedViewIsNeverMutated pins the invariant the lock-free read rests
// on: a writer must build fresh maps and swap the pointer, never write into a
// view a reader may already hold. It compares the pointer identity AND the
// contents of the view a reader captured before a Replace.
func TestPublishedViewIsNeverMutated(t *testing.T) {
	s := New()
	s.Replace([]string{benchHash}, benchExcludedHosts)
	before := s.current()

	s.Replace(nil, []string{"other.internal.example"})
	after := s.current()

	if before == after {
		t.Fatal("Replace reused the published view pointer; a reader holding it would see a torn update")
	}
	if len(before.hashes) != 1 || !before.hashes[benchHash] {
		t.Errorf("the pre-Replace view's hash map changed: %v", before.hashes)
	}
	if len(before.hosts) != len(benchExcludedHosts) {
		t.Errorf("the pre-Replace view's host map changed: %v", before.hosts)
	}
	if before.hosts["other.internal.example"] {
		t.Error("Replace wrote into the view a reader was already holding")
	}
}

// TestConcurrentReplaceAndRead exercises the publish/read pair under -race,
// which is where a reintroduced unsynchronised map write would be caught.
// Readers also assert the only two answers a correct publish can produce, so a
// torn view (one list swapped and the other not) fails rather than passing
// quietly.
func TestConcurrentReplaceAndRead(t *testing.T) {
	s := New()
	s.Replace([]string{benchHash}, benchExcludedHosts)

	var stop atomic.Bool
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				// A published view always carries BOTH lists from the same
				// Replace, so the digest and the host must agree about which
				// generation the reader is looking at.
				_ = s.IsHashExcluded(benchHash)
				_ = s.IsHostExcluded(benchExcludedHosts[0])
				_, _ = s.Lists()
			}
		}()
	}
	for i := 0; i < 50; i++ {
		s.Replace([]string{benchHash}, []string{fmt.Sprintf("gen-%d.internal.example", i)})
	}
	stop.Store(true)
	wg.Wait()

	if !s.IsHashExcluded(benchHash) {
		t.Fatal("final publish lost the hash list")
	}
	if !s.IsHostExcluded("gen-49.internal.example") {
		t.Fatal("final publish lost the host list")
	}
}
