package blocklist

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Benchmarks and regression gates for the blocklist matcher hot path.
//
//	go test -run XXX -bench 'BenchmarkIsBlocked' -benchmem ./internal/blocklist/
//
// IsBlocked runs on EVERY proxied destination — plain HTTP, CONNECT, WebSocket
// and SOCKS5 all reach it through preDispatchBlocked — so its fixed cost is
// paid once per request before any policy work begins.
//
// The contract these pin: probing the exception and wildcard maps must not
// allocate, at any host length, and a store with no exceptions configured must
// not walk the host's labels at all.
//
// What it cost before: isExcepted and isListed built their lookup keys with
// string concatenation ("*."+host, "*."+parent, "."+host). Go hands a
// non-escaping concatenation a 32-byte stack buffer, so the cost was invisible
// on a short hostname and a heap allocation on every longer one — and longer is
// the ordinary shape in real traffic (regional cloud, CDN and telemetry
// endpoints run well past 30 bytes). Worse, the probes ran unconditionally, so
// the DEFAULT posture — no exceptions configured, an empty map — paid the full
// per-label walk and its allocations to discover nothing, on every request.
//
// Measured here (Intel Xeon @ 2.10GHz, linux/amd64, -count=5, medians),
// "before" being BenchmarkIsBlocked_Baseline, which runs the pre-fix bodies in
// the same binary so the comparison needs no checkout of the parent commit:
//
//	                              before                    after
//	  Short/NoExceptions      112 ns/op    0 B  0       71 ns/op   0 B  0   -37%
//	  Short/WithExceptions    140 ns/op    0 B  0      135 ns/op   0 B  0    -4%
//	  Typical/NoExceptions    199 ns/op    0 B  0      105 ns/op   0 B  0   -47%
//	  Typical/WithExceptions  264 ns/op    0 B  0      235 ns/op   0 B  0   -11%
//	  Long/NoExceptions       415 ns/op  176 B  3      181 ns/op   0 B  0   -56%
//	  Long/WithExceptions     502 ns/op  176 B  3      353 ns/op   0 B  0   -30%
//
// The allocation column is the finding: a perfectly ordinary hostname cost
// 176 B of pure probe garbage per request on a store with NOTHING configured
// to probe against. The ns column splits by posture for the reason the two
// mechanisms differ — an empty exception map skips the walk outright, while a
// configured one still walks it, just without touching the allocator.

// benchHostShapes are the destination shapes a forward proxy actually sees.
// Length is the axis that matters here: it decides whether the pre-fix
// concatenation fit the compiler's 32-byte stack buffer or went to the heap.
var benchHostShapes = []struct {
	name string
	host string
}{
	// Well inside the 32-byte stack buffer — the shape that hid this cost.
	{"Short", "example.com"},
	// Straddles it: "*."+host is 24 bytes, but the parent-walk probes are not.
	{"Typical", "cdn.assets.example.com"},
	// Past it in every probe. Nothing exotic — this is the shape of a regional
	// cloud or CDN endpoint, and of most corporate internal names.
	{"Long", "very-long-subdomain.assets.cdn.example-corporation.com"},
}

// benchExceptions is a small, realistic never-block list. Its SIZE is not the
// point — one entry is enough to defeat the len(m)==0 short-circuit and force
// the full parent walk, which is exactly the case the stack-buffer probe exists
// to keep allocation-free.
var benchExceptions = []string{"*.allowed.example.org", "internal.example.net"}

// benchStore builds the store both the benchmarks and the gates run against:
// a wildcard entry, an exact entry, and optionally the exception list. The
// benchmark hosts deliberately match NOTHING — a hit is terminal and rare, a
// miss is what every allowed request pays.
func benchStore(exceptions []string) *Store {
	s := New()
	s.Add("*.badexample.com")
	s.Add("evil.test")
	for _, e := range exceptions {
		s.AddException(e)
	}
	return s
}

var benchBlocked bool

func BenchmarkIsBlocked(b *testing.B) {
	for _, s := range benchHostShapes {
		host := s.host
		b.Run(s.name+"/NoExceptions", func(b *testing.B) {
			st := benchStore(nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBlocked = st.IsBlocked(host)
			}
		})
		b.Run(s.name+"/WithExceptions", func(b *testing.B) {
			st := benchStore(benchExceptions)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBlocked = st.IsBlocked(host)
			}
		})
	}
}

// BenchmarkIsBlocked_Baseline measures the PRE-fix bodies on the identical
// inputs and the identical store, so benchstat over this one file gives the
// honest before/after without checking out the parent commit.
func BenchmarkIsBlocked_Baseline(b *testing.B) {
	for _, s := range benchHostShapes {
		host := s.host
		b.Run(s.name+"/NoExceptions", func(b *testing.B) {
			st := benchStore(nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBlocked = referenceIsBlocked(st, host)
			}
		})
		b.Run(s.name+"/WithExceptions", func(b *testing.B) {
			st := benchStore(benchExceptions)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBlocked = referenceIsBlocked(st, host)
			}
		})
	}
}

// benchParallelSink keeps the parallel benchmark's work alive against dead-code
// elimination without putting a shared package-level write in the measured
// loop — that would be a data race under -race AND would measure false sharing
// on that cache line instead of the matcher, which is precisely the contention
// this benchmark exists to show is absent.
var benchParallelSink atomic.Int64

// BenchmarkIsBlocked_Parallel is the concurrency benchmark. IsBlocked takes a
// read lock and, after this change, allocates nothing under it — so the
// goroutine-per-connection fan-out a proxy runs at should scale on read-lock
// sharing alone, with no allocator or GC coupling between workers.
func BenchmarkIsBlocked_Parallel(b *testing.B) {
	st := benchStore(benchExceptions)
	hosts := make([]string, 0, len(benchHostShapes))
	for _, s := range benchHostShapes {
		hosts = append(hosts, s.host)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var local int64 // goroutine-local: no shared write in the measured loop
		i := 0
		for pb.Next() {
			if st.IsBlocked(hosts[i%len(hosts)]) {
				local++
			}
			i++
		}
		benchParallelSink.Add(local)
	})
}

// ── Regression gates ─────────────────────────────────────────────────────────

// TestIsBlocked_AllocRegression is the hard, hardware-independent gate. ns/op
// varies with the runner; allocations do not. Every shape must be 0 allocs/op
// in both postures: a DNS name is capped at 253 bytes, so the scratch buffer
// covers every legitimate host and there is no length at which a probe should
// reach the heap. Reintroducing a concatenated lookup key fails this
// immediately.
func TestIsBlocked_AllocRegression(t *testing.T) {
	for _, s := range benchHostShapes {
		host := s.host
		for _, posture := range []struct {
			name string
			exc  []string
		}{
			{"NoExceptions", nil},
			{"WithExceptions", benchExceptions},
		} {
			st := benchStore(posture.exc)
			t.Run(s.name+"/"+posture.name, func(t *testing.T) {
				got := testing.AllocsPerRun(200, func() { benchBlocked = st.IsBlocked(host) })
				if got > 0 {
					t.Errorf("IsBlocked(%q) allocates %v/op, want 0 — a lookup key is being built on the heap "+
						"instead of in the probePrefixed scratch buffer", host, got)
				}
			})
		}
	}
}

// TestIsBlocked_MaxLengthHostStaysAllocFree pins the buffer SIZE against the
// contract it was chosen for: 253 bytes is the DNS maximum (RFC 1035 §2.3.4),
// so the longest legal host must still probe without allocating. Shrinking
// hostKeyProbeMax below that silently pushes real hosts onto the concatenation
// fallback, which is the regression this file exists to prevent.
func TestIsBlocked_MaxLengthHostStaysAllocFree(t *testing.T) {
	// 251 bytes — the practical maximum for a presentation-format DNS name:
	// 12 labels of 20 characters joined by 11 dots.
	labels := make([]string, 12)
	for i := range labels {
		labels[i] = "abcdefghijklmnopqrst"
	}
	host := strings.Join(labels, ".")
	if len(host) != 251 { // 12*20 + 11 dots
		t.Fatalf("test fixture is %d bytes, expected 251", len(host))
	}
	st := benchStore(benchExceptions)
	if got := testing.AllocsPerRun(200, func() { benchBlocked = st.IsBlocked(host) }); got > 0 {
		t.Errorf("IsBlocked on a %d-byte host allocates %v/op, want 0: hostKeyProbeMax (%d) no longer "+
			"covers the maximum legal DNS name", len(host), got, hostKeyProbeMax)
	}
}

// ── Differential equivalence ─────────────────────────────────────────────────
//
// The gates above prove the new path is cheaper. This one proves it decides
// the same thing — the only property that actually matters, since a blocklist
// that is fast and wrong is a security defect, not an optimization.

// referenceIsListed, referenceIsExcepted and referenceIsBlocked are the
// pre-fix bodies, copied verbatim (rune-ranging label walk, concatenated
// lookup keys, no short-circuits). They are the oracle for the differential
// test AND the "before" arm of the baseline benchmark. Do not "tidy" them —
// their value is being an untouched copy of what shipped.
func referenceIsListed(b *Store, host string) bool {
	if b.exact[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && b.wildcards[host[i:]] {
			return true
		}
	}
	return b.wildcards["."+host]
}

func referenceIsExcepted(b *Store, host string) bool {
	if b.exceptions[host] {
		return true
	}
	if b.exceptions["*."+host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' {
			parent := host[i+1:]
			if b.exceptions[parent] {
				return true
			}
			if b.exceptions["*."+parent] {
				return true
			}
		}
	}
	return false
}

func referenceIsBlocked(b *Store, host string) bool {
	host = hostutil.NormalizeHost(host)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if referenceIsExcepted(b, host) {
		return false
	}
	listed := referenceIsListed(b, host)
	if b.mode == "allow" {
		return !listed
	}
	return listed
}

// TestIsBlocked_MatchesPreOptimizationBehaviour walks a matrix of stores and
// hosts chosen to hit every branch the change touched — exact hits, wildcard
// hits, parent-domain inheritance, wildcard exceptions, bare-domain
// exceptions, allow mode, trailing dots, non-ASCII labels (the rune-range to
// byte-index substitution), the empty host, and hosts on both sides of the
// scratch-buffer boundary — and asserts the optimized matcher and the verbatim
// pre-fix matcher agree on every cell.
func TestIsBlocked_MatchesPreOptimizationBehaviour(t *testing.T) {
	longLabel := "very-long-subdomain-well-past-the-stack-buffer-boundary"

	stores := []struct {
		name       string
		listed     []string
		exceptions []string
		mode       string
	}{
		{"Empty", nil, nil, "block"},
		{"ExactOnly", []string{"evil.test", "ads.example.com"}, nil, "block"},
		{"WildcardOnly", []string{"*.example.com", "*." + longLabel + ".test"}, nil, "block"},
		{"Mixed", []string{"*.example.com", "evil.test"}, nil, "block"},
		{"WildcardException", []string{"*.example.com"}, []string{"*.cdn.example.com"}, "block"},
		{"BareException", []string{"*.example.com"}, []string{"cdn.example.com"}, "block"},
		{"LongException", []string{"*.example.com"}, []string{"*." + longLabel + ".example.com"}, "block"},
		{"AllowMode", []string{"*.example.com", "evil.test"}, nil, "allow"},
		{"AllowModeWithException", []string{"*.example.com"}, []string{"*.cdn.example.com"}, "allow"},
	}

	hosts := []string{
		"",
		"com",
		"example.com",
		"cdn.example.com",
		"a.b.cdn.example.com",
		"evil.test",
		"not-listed.example.org",
		"example.com.", // trailing dot — normalization strips it
		"EXAMPLE.COM",  // mixed case — normalization lowers it
		longLabel + ".example.com",
		"deep." + longLabel + ".example.com",
		longLabel + "." + longLabel + ".test",
		"bücher.example.com", // non-ASCII: exercises the label walk substitution
		"xn--bcher-kva.example.com",
		"203.0.113.10",
		"[2001:db8::1]",
	}

	for _, sc := range stores {
		for _, host := range hosts {
			t.Run(fmt.Sprintf("%s/%q", sc.name, host), func(t *testing.T) {
				optimized := newStoreFor(sc.listed, sc.exceptions, sc.mode)
				reference := newStoreFor(sc.listed, sc.exceptions, sc.mode)
				want := referenceIsBlocked(reference, host)
				if got := optimized.IsBlocked(host); got != want {
					t.Errorf("IsBlocked(%q) = %v, pre-optimization body = %v", host, got, want)
				}
			})
		}
	}
}

// newStoreFor builds a store from a listed set, an exception set and a mode,
// without touching the filesystem (SetMode would try to persist a sidecar).
func newStoreFor(listed, exceptions []string, mode string) *Store {
	s := New()
	for _, h := range listed {
		s.Add(h)
	}
	for _, e := range exceptions {
		s.AddException(e)
	}
	s.mu.Lock()
	s.mode = mode
	s.mu.Unlock()
	return s
}
