package hostutil

import (
	"fmt"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Tests and benchmarks for the memoized IDNA slow path (idnamemo.go).
//
//	go test -run 'IDNMemo' -bench 'IDN' -benchmem ./internal/hostutil/
//
// Measured on Intel Xeon @ 2.10GHz, linux/amd64, Go 1.26, -count=6. Every "no
// memo" row runs the frozen pre-change body (normalizeHostStrictUncached) in the
// SAME binary on the SAME input, so the comparison needs no checkout of the
// parent commit and no cross-run normalization.
//
//	                         no memo                       memoized
//	ACELabel                 719 ns   256 B   7 allocs      54 ns    0 B   0
//	UnicodeIDN               510 ns   192 B   5 allocs      90 ns    0 B   0
//	ACEMultiLabel            948 ns   304 B   9 allocs      70 ns    0 B   0
//	UnicodeCJK               523 ns   184 B   5 allocs      89 ns    0 B   0
//	MalformedACE             311 ns   136 B   4 allocs      31 ns    0 B   0
//	RequestFanout   (x10)   6900 ns  2560 B  70 allocs     554 ns    0 B   0
//	ColdFanout      (x10)   6780 ns  1980 B  50 allocs    1819 ns  265 B   6
//	Parallel (4 cores, warm)      --                        17 ns    0 B   0
//	Thrash (isolated miss)   629 ns   198 B   5 allocs     766 ns  265 B   6
//
// Read the last three rows together, because they are what decides whether the
// memo is safe to ship:
//
//   - RequestFanout is the steady state: one request to a destination the proxy
//     has seen before. -92% CPU, and the 70 allocations become none.
//   - ColdFanout is the same request to a destination NEVER seen before — no
//     reuse across requests at all, the shape an adversary would aim for. Still
//     -73% CPU and -88% allocations, because the fan-out itself supplies the
//     reuse: one engine misses and the other nine hit.
//   - Thrash is the only row where the memo loses: a SINGLE isolated lookup of a
//     never-seen host, +22% ns and +1 allocation for the hash, the key clone and
//     the entry. The request path cannot produce that shape — it always does the
//     fan-out, i.e. the row above — so this is a floor on the overhead rather
//     than a scenario, and it is reported here instead of being left out.
//
// The ASCII fast path is untouched and must stay 0-alloc: pinned by
// TestIDNMemo_FastPathNeverTouchesMemo and the existing
// TestNormalizeHostStrict_AllocRegression.
//
// The footprint ceiling this file asserts holds only because no entry may carry
// a string longer than maxMemoHostLen. That is not incidental: the HTTP raw gate
// admits a 1 KiB authority and the 253-byte canonical refusal runs after
// canonicalDestHost has already normalized it, so an oversize ACE host used to be
// retained whole. TestIDNMemo_OversizeHostsAreNotRetained and
// TestIDNMemo_StoredEntriesRespectTheBound are the gates for that; both were
// verified failing against the verbatim pre-fix body.

// idnShapes are the internationalized destination shapes that reach the slow
// path. ACELabel is the one that matters most: browsers send the A-label in the
// Host header and the CONNECT authority, so it is the live shape of every
// request to an internationalized domain.
var idnShapes = []struct {
	name string
	host string
}{
	{"ACELabel", "xn--bcher-kva.example.com"},
	{"UnicodeIDN", "bücher.example.com"},
	{"ACEMultiLabel", "xn--fsq.xn--bcher-kva.example.com"},
	{"UnicodeCJK", "日本.example.com"},
	{"MalformedACE", "xn--.com"},
}

var (
	benchIDNNorm string
	benchIDNOK   bool
)

// normMemoResetForTest empties the table so a test can measure the cold path or
// start from a known state. Tests in this package run sequentially unless they
// call t.Parallel(), which none of the tests that reset do.
func normMemoResetForTest() {
	for i := range normMemo {
		normMemo[i].Store(nil)
	}
}

// normMemoOccupied counts filled slots — the table's live entry count.
func normMemoOccupied() int {
	n := 0
	for i := range normMemo {
		if normMemo[i].Load() != nil {
			n++
		}
	}
	return n
}

// normMemoRetainedBytes is the bytes the table itself keeps alive: the slot
// array plus, for every live entry, the entry header and both of its strings.
// This is the figure the fixed-capacity design exists to bound.
func normMemoRetainedBytes() int {
	const slotPtr = 8   // atomic.Pointer
	const entryHdr = 40 // two string headers (16 each) + bool, padded
	total := len(normMemo) * slotPtr
	for i := range normMemo {
		if e := normMemo[i].Load(); e != nil {
			total += entryHdr + len(e.host) + len(e.norm)
		}
	}
	return total
}

// ── Correctness ─────────────────────────────────────────────────────────────

// TestIDNMemo_MatchesUncached is the differential: for every slow-path shape the
// memoized result must equal what the frozen uncached body computes, on the cold
// call AND on every repeat. A memo that returned a stale or crossed answer fails
// here. (FuzzNormalizeHostStrict in hostutil_fastpath_test.go carries the
// open-ended half of the same proof, against the pre-fast-path reference.)
func TestIDNMemo_MatchesUncached(t *testing.T) {
	normMemoResetForTest()
	for _, h := range fastPathCorpus() {
		lowered := strings.ToLower(strings.TrimSuffix(h, "."))
		if lowered == "" || isCanonicalASCIIHost(lowered) {
			continue // fast path; never reaches the memo
		}
		wantNorm, wantOK := normalizeHostStrictUncached(lowered)
		for round := 0; round < 3; round++ {
			gotNorm, gotOK := NormalizeHostStrict(h)
			if gotNorm != wantNorm || gotOK != wantOK {
				t.Fatalf("NormalizeHostStrict(%q) round %d = (%q, %v), uncached = (%q, %v)",
					h, round, gotNorm, gotOK, wantNorm, wantOK)
			}
		}
	}
}

// TestIDNMemo_CollisionAnswersBothHosts is the direct-mapped design's load-bearing
// property: two hosts that land in the SAME slot must each get their own answer.
// The entry re-verifies the full key on every hit, so a collision costs a
// recomputation and never produces the other host's result. The colliding pair is
// found at runtime because the slot seed is randomized per process.
func TestIDNMemo_CollisionAnswersBothHosts(t *testing.T) {
	normMemoResetForTest()
	a, b, found := findCollidingIDNHosts(1 << 16)
	if !found {
		t.Skip("no colliding pair found in the search budget (seed-dependent)")
	}
	wantA, okA := normalizeHostStrictUncached(a)
	wantB, okB := normalizeHostStrictUncached(b)
	if wantA == wantB {
		t.Fatalf("colliding probe hosts normalize identically (%q); the test proves nothing", wantA)
	}
	// Alternate so each lookup finds the OTHER host resident in the shared slot.
	for round := 0; round < 4; round++ {
		if got, ok := NormalizeHostStrict(a); got != wantA || ok != okA {
			t.Fatalf("round %d: NormalizeHostStrict(%q) = (%q, %v), want (%q, %v)", round, a, got, ok, wantA, okA)
		}
		if got, ok := NormalizeHostStrict(b); got != wantB || ok != okB {
			t.Fatalf("round %d: NormalizeHostStrict(%q) = (%q, %v), want (%q, %v)", round, b, got, ok, wantB, okB)
		}
	}
}

// findCollidingIDNHosts searches generated Unicode hosts for two that map to the
// same slot under this process's seed.
func findCollidingIDNHosts(budget int) (a, b string, found bool) {
	seen := make(map[uint64]string, budget)
	for i := 0; i < budget; i++ {
		h := fmt.Sprintf("bücher%d.example.com", i)
		slot := maphash.String(normMemoSeed, h) & normMemoMask
		if prev, ok := seen[slot]; ok {
			return prev, h, true
		}
		seen[slot] = h
	}
	return "", "", false
}

// TestIDNMemo_FastPathNeverTouchesMemo pins that ordinary ASCII traffic — the
// common case — neither reads nor writes the table. If a refactor moved the memo
// ahead of the already-canonical fast path, every request would start paying a
// hash and a pointer load for nothing, and the table would fill with hosts that
// never needed it.
func TestIDNMemo_FastPathNeverTouchesMemo(t *testing.T) {
	normMemoResetForTest()
	for _, h := range []string{
		"example.com", "sub.cdn.assets.example.com", "203.0.113.10",
		"[2001:db8::1]", "r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com",
	} {
		if _, ok := NormalizeHostStrict(h); !ok {
			t.Fatalf("NormalizeHostStrict(%q) rejected a valid host", h)
		}
	}
	if n := normMemoOccupied(); n != 0 {
		t.Errorf("REGRESSION: %d memo slots filled by fast-path hosts, want 0 — "+
			"the memo must sit BEHIND the already-canonical fast path", n)
	}
}

// ── Allocation and memory ───────────────────────────────────────────────────

// TestIDNMemo_AllocRegression is the hard, hardware-independent gate. ns/op
// varies by runner; allocations do not. The pre-change body allocated 5-7 per
// call on a path that runs ~10x per proxied request, i.e. ~70 allocations per
// request to an internationalized domain. A warm lookup must allocate NOTHING.
func TestIDNMemo_AllocRegression(t *testing.T) {
	for _, s := range idnShapes {
		host := s.host
		t.Run(s.name, func(t *testing.T) {
			// AllocsPerRun calls fn once before measuring, which fills the slot.
			got := allocCount(func() { benchIDNNorm, benchIDNOK = NormalizeHostStrict(host) })
			if got != 0 {
				t.Errorf("REGRESSION: NormalizeHostStrict(%q) allocates %.0f/op warm, want 0. "+
					"This path runs ~10x per proxied request; an allocation here is ~10 per request.",
					host, got)
			}
		})
	}
}

// TestIDNMemo_OversizeHostsAreNotRetained is the regression gate for the bound
// the first revision of this file asserted but did not hold (CodeRabbit on
// PR #1598). The HTTP raw pre-cap admits a 1 KiB destination authority and the
// 253-byte canonical refusal runs AFTER canonicalDestHost has normalized it, and
// the zero-option idna.ToASCII profile enforces no length limit of its own — so
// a ~1 KiB ACE authority used to be cloned into a slot whole (measured: a
// 998-byte host stored as len(host)=998, len(norm)=998, i.e. ~2.1 MB across a
// full table against the 554 KB this file claims). The verdict is unchanged
// either way; only retention is.
func TestIDNMemo_OversizeHostsAreNotRetained(t *testing.T) {
	oversize := []struct {
		name string
		host string
	}{
		// What the 1 KiB raw gate admits, with an ACE label so it reaches the
		// slow path rather than the already-canonical fast path.
		{"ValidACE", "xn--bcher-kva." + strings.Repeat("a", 980) + ".com"},
		// The ok=false shape: a malformed ACE label on an oversize authority.
		{"MalformedACE", "xn--." + strings.Repeat("b", 990) + ".com"},
		// Non-ASCII, so the fast path rejects it and idna does the work.
		{"Unicode", strings.Repeat("ü", 400) + ".example.com"},
		// Exactly one byte over the limit — the boundary.
		{"OneOverLimit", "xn--bcher-kva." + strings.Repeat("c", maxMemoHostLen-13) + ".de"},
	}
	for _, c := range oversize {
		t.Run(c.name, func(t *testing.T) {
			normMemoResetForTest()
			lowered := strings.ToLower(strings.TrimSuffix(c.host, "."))
			if len(lowered) <= maxMemoHostLen {
				t.Fatalf("probe host is %d bytes, not oversize — the case proves nothing", len(lowered))
			}
			wantNorm, wantOK := normalizeHostStrictUncached(lowered)
			// The answer must be identical: this is about retention only.
			for round := 0; round < 3; round++ {
				gotNorm, gotOK := NormalizeHostStrict(c.host)
				if gotNorm != wantNorm || gotOK != wantOK {
					t.Fatalf("round %d: got (%q…, %v), uncached (%q…, %v)",
						round, truncForLog(gotNorm), gotOK, truncForLog(wantNorm), wantOK)
				}
			}
			if n := normMemoOccupied(); n != 0 {
				t.Errorf("REGRESSION: %d slots filled by a %d-byte host — an oversize host "+
					"must be normalized but never retained, or the footprint ceiling does not hold",
					n, len(lowered))
			}
		})
	}
}

// expandingIDNHost builds the host shape that maximizes punycode EXPANSION:
// unit repeated as dot-separated labels, up to maxMemoHostLen bytes total.
//
// The ACE overhead ("xn--" + the "-" delimiter + the encoded deltas) is paid
// per LABEL, so the worst case is many SHORT labels each carrying one non-ASCII
// rune — the opposite of the dense-script shape, where one label amortizes the
// overhead across many runes and the A-label comes out shorter than the input.
// prefix makes the host distinct without changing the shape.
func expandingIDNHost(prefix, unit string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for b.Len()+len(unit)+1 <= maxMemoHostLen {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(unit)
	}
	return b.String()
}

// TestIDNMemo_PunycodeExpansionIsNotRetained is the gate for the SECOND half of
// the footprint bound — the len(norm) check in normalizeHostStrictMemo — which
// shipped without one.
//
// The ceiling needs BOTH checks, because a host can breach it from either side:
// by arriving oversize (the len(host) check, gated by
// TestIDNMemo_OversizeHostsAreNotRetained after CodeRabbit found that bound did
// not hold), or by arriving within the limit and EXPANDING past it through
// punycode. Only the first was gated. Measured with the len(norm) branch
// deleted, the whole package suite stayed green while the table retained
// 969 KB against its 554 KB ceiling, with a 668-byte norm in a slot — the same
// class of breach, and the same magnitude, as the one the first check fixes.
//
// The gap was in the corpus, not the intent:
// TestIDNMemo_StoredEntriesRespectTheBound deliberately feeds "inputs whose
// punycode form is longer than their ASCII byte count suggests", but reaches
// for CJK, which COMPRESSES (a 252-byte CJK host measures 98 bytes as an
// A-label). Expansion needs one non-ASCII rune in each of many short labels.
//
// Each case must therefore be in-limit on the way in (so the len(host) check
// does not fire and this branch is the only thing standing between the host and
// a slot) and over the limit on the way out. Both preconditions are asserted,
// so the test fails loudly if a future x/net changes the encoding rather than
// passing vacuously.
func TestIDNMemo_PunycodeExpansionIsNotRetained(t *testing.T) {
	for _, c := range []struct {
		name string
		unit string
	}{
		// Shortest possible label: one non-ASCII rune, so the per-label ACE
		// overhead is amortized over nothing. 251 bytes in, 671 out.
		{"BareRunePerLabel", "é"},
		// One ASCII byte alongside it — the shape a real IDN label resembles.
		{"RunePlusASCII", "aé"},
		// Longer labels: less expansion per label, still over the bound.
		{"RunePlusTwoASCII", "aaé"},
		// A non-Latin rune, to show the shape and not the script is what matters.
		{"CyrillicPerLabel", "д"},
	} {
		t.Run(c.name, func(t *testing.T) {
			normMemoResetForTest()
			host := expandingIDNHost("", c.unit)
			lowered := strings.ToLower(strings.TrimSuffix(host, "."))

			// Precondition 1: in-limit on the way in, so the len(host) check
			// above cannot be what keeps this host out of the table.
			if len(lowered) > maxMemoHostLen {
				t.Fatalf("probe host is %d bytes, over the %d-byte limit — the "+
					"len(host) check would reject it and this case proves nothing",
					len(lowered), maxMemoHostLen)
			}
			wantNorm, wantOK := normalizeHostStrictUncached(lowered)
			// Precondition 2: it must actually expand past the bound, or this
			// is not the branch under test.
			if !wantOK {
				t.Fatalf("probe host does not normalize (ok=false); the case proves nothing")
			}
			if len(wantNorm) <= maxMemoHostLen {
				t.Fatalf("probe host normalizes to %d bytes, within the %d-byte bound — "+
					"this case no longer exercises the len(norm) branch (did the "+
					"x/net encoding change?)", len(wantNorm), maxMemoHostLen)
			}

			// The verdict is unchanged: this is about RETENTION only. An
			// expanding host is still normalized, on every call.
			for round := 0; round < 3; round++ {
				gotNorm, gotOK := NormalizeHostStrict(host)
				if gotNorm != wantNorm || gotOK != wantOK {
					t.Fatalf("round %d: got (%q…, %v), uncached (%q…, %v)",
						round, truncForLog(gotNorm), gotOK, truncForLog(wantNorm), wantOK)
				}
			}
			if n := normMemoOccupied(); n != 0 {
				t.Errorf("REGRESSION: %d slot(s) filled by a %d-byte host whose canonical "+
					"form is %d bytes — an entry may never carry a string longer than %d, "+
					"or the footprint ceiling does not hold",
					n, len(lowered), len(wantNorm), maxMemoHostLen)
			}
		})
	}
}

// TestIDNMemo_ExpansionCannotBreachTheCeiling is the memory half of the gate
// above: not "one such host is refused a slot" but "a client sending nothing
// BUT such hosts cannot push the table past its ceiling". It is the
// TestIDNMemo_BoundedFootprint argument run against the expanding shape, which
// is the shape that actually threatens the bound — distinct hosts there are
// bounded by the slot count, but retained BYTES are bounded only by the
// per-entry length check.
func TestIDNMemo_ExpansionCannotBreachTheCeiling(t *testing.T) {
	normMemoResetForTest()
	const distinct = normMemoSlots * 8
	for i := 0; i < distinct; i++ {
		NormalizeHostStrict(expandingIDNHost(fmt.Sprintf("%d", i), "é"))
	}
	// Same ceiling as TestIDNMemo_BoundedFootprint: every slot filled with two
	// maximum-length DNS names.
	ceiling := len(normMemo)*8 + normMemoSlots*(40+2*maxMemoHostLen)
	retained := normMemoRetainedBytes()
	if retained > ceiling {
		t.Fatalf("REGRESSION: memo retains %d B after %d distinct expanding IDN hosts, "+
			"ceiling %d B — the len(norm) check is what holds this bound",
			retained, distinct, ceiling)
	}
	t.Logf("after %d distinct expanding IDN hosts: %d/%d slots, %d B retained (ceiling %d B)",
		distinct, normMemoOccupied(), normMemoSlots, retained, ceiling)
}

// truncForLog keeps a failure message from dumping a kilobyte-long host.
func truncForLog(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

// TestIDNMemo_StoredEntriesRespectTheBound asserts the footprint invariant
// directly, over whatever the table actually ended up holding, rather than over
// the one code path that enforces it: no live entry may carry a string longer
// than maxMemoHostLen. That is what makes the ceiling in
// TestIDNMemo_BoundedFootprint a bound rather than a measurement of one corpus.
func TestIDNMemo_StoredEntriesRespectTheBound(t *testing.T) {
	normMemoResetForTest()
	// A corpus that mixes in-limit, boundary and oversize shapes, plus inputs
	// whose punycode form is longer than their ASCII byte count suggests.
	corpus := append([]string{}, fastPathCorpus()...)
	corpus = append(corpus,
		"xn--bcher-kva."+strings.Repeat("a", 980)+".com",
		strings.Repeat("ü", 400)+".example.com",
		strings.Repeat("日", 80)+".example.com",
		strings.Repeat("日", 84)+".example.com",
		"xn--."+strings.Repeat("b", 990)+".com",
		strings.Repeat("xn--fsq.", 120)+"com",
		// The two CJK rows above were meant to be the "longer punycode form
		// than the byte count suggests" cases, but a dense script COMPRESSES:
		// both normalize well inside the bound (the 84-rune one is refused by
		// the len(host) check, not the len(norm) one). Expansion needs one
		// non-ASCII rune per short label, so the real cases go in here —
		// otherwise this invariant holds vacuously on that axis and the
		// len(norm) check has no coverage at all.
		expandingIDNHost("", "é"),
		expandingIDNHost("", "aé"),
		expandingIDNHost("", "д"),
	)
	for i := 0; i < 64; i++ {
		corpus = append(corpus, fmt.Sprintf("bücher%d.example.com", i))
	}
	for _, h := range corpus {
		NormalizeHostStrict(h)
	}
	for i := range normMemo {
		e := normMemo[i].Load()
		if e == nil {
			continue
		}
		if len(e.host) > maxMemoHostLen || len(e.norm) > maxMemoHostLen {
			t.Fatalf("slot %d holds len(host)=%d len(norm)=%d, both must be <= %d",
				i, len(e.host), len(e.norm), maxMemoHostLen)
		}
	}
}

// TestIDNMemo_BoundedFootprint is the memory test: the key is a client-chosen
// destination authority, so the table must not grow with the number of distinct
// hosts seen. Feeding it 64x more distinct IDN hosts than it has slots must leave
// the slot count and the retained bytes at the fixed ceiling.
func TestIDNMemo_BoundedFootprint(t *testing.T) {
	normMemoResetForTest()
	const distinct = normMemoSlots * 64
	for i := 0; i < distinct; i++ {
		NormalizeHostStrict(fmt.Sprintf("bücher%d.example.com", i))
	}
	occupied := normMemoOccupied()
	if occupied > normMemoSlots {
		t.Fatalf("memo holds %d entries after %d distinct hosts, ceiling %d", occupied, distinct, normMemoSlots)
	}
	// Absolute ceiling: every slot filled with two maximum-length DNS names.
	// It is a real ceiling only because no entry may exceed maxMemoHostLen —
	// asserted over the live table by TestIDNMemo_StoredEntriesRespectTheBound
	// and at the boundary by TestIDNMemo_OversizeHostsAreNotRetained.
	ceiling := len(normMemo)*8 + normMemoSlots*(40+2*maxMemoHostLen)
	retained := normMemoRetainedBytes()
	if retained > ceiling {
		t.Fatalf("memo retains %d B after %d distinct hosts, ceiling %d B", retained, distinct, ceiling)
	}
	t.Logf("after %d distinct IDN hosts: %d/%d slots, %d B retained (ceiling %d B)",
		distinct, occupied, normMemoSlots, retained, ceiling)
}

// ── Concurrency and stress ──────────────────────────────────────────────────

// TestIDNMemo_ConcurrentStress is the stress test: entries are immutable and
// published by a single atomic store, so concurrent readers and writers over a
// host set far larger than the table — i.e. under continuous eviction — must stay
// race-free and keep returning the uncached answer. Run under -race.
func TestIDNMemo_ConcurrentStress(t *testing.T) {
	normMemoResetForTest()
	// Deliberately more hosts than slots, so workers evict each other's entries
	// throughout the run instead of settling into a resident working set.
	const hostCount = normMemoSlots * 4
	hosts := make([]string, hostCount)
	wantNorm := make([]string, hostCount)
	wantOK := make([]bool, hostCount)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("bücher%d.example.com", i)
		wantNorm[i], wantOK[i] = normalizeHostStrictUncached(hosts[i])
	}

	// Sized to keep the default and -race lanes quick while still driving many
	// millions of lookups through continuous eviction: 8 workers x 40 passes over
	// 4096 hosts is ~1.3M normalizations, every one of them verified.
	const goroutines, iterations = 8, 40
	var mismatches atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		start := g
		go func() {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				for k := 0; k < hostCount; k++ {
					i := (start*iterations + it + k) % hostCount
					norm, ok := NormalizeHostStrict(hosts[i])
					if norm != wantNorm[i] || ok != wantOK[i] {
						mismatches.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()
	if n := mismatches.Load(); n != 0 {
		t.Fatalf("%d results diverged from the uncached reference under concurrent eviction", n)
	}
	if occupied := normMemoOccupied(); occupied > normMemoSlots {
		t.Fatalf("memo grew to %d entries under stress, ceiling %d", occupied, normMemoSlots)
	}
}

// ── Benchmarks ──────────────────────────────────────────────────────────────

// BenchmarkNormalizeHostStrict_IDNMemo measures the shipped memoized path on a
// resident host: the steady state for a destination the proxy has seen before.
func BenchmarkNormalizeHostStrict_IDNMemo(b *testing.B) {
	for _, s := range idnShapes {
		b.Run(s.name, func(b *testing.B) {
			benchIDNNorm, benchIDNOK = NormalizeHostStrict(s.host) // fill the slot
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchIDNNorm, benchIDNOK = NormalizeHostStrict(s.host)
			}
		})
	}
}

// BenchmarkNormalizeHostStrict_IDNNoMemo measures the FROZEN pre-change body on
// the identical inputs, so benchstat over this file alone gives the honest
// before/after without checking out the parent commit.
func BenchmarkNormalizeHostStrict_IDNNoMemo(b *testing.B) {
	for _, s := range idnShapes {
		b.Run(s.name, func(b *testing.B) {
			host := strings.ToLower(strings.TrimSuffix(s.host, "."))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchIDNNorm, benchIDNOK = normalizeHostStrictUncached(host)
			}
		})
	}
}

// perRequestNormalizations is the number of independent engines that normalize
// the same destination host on one proxied request (see idnamemo.go). It mirrors
// BenchmarkNormalizeHostStrict_RequestFanout's constant.
const perRequestNormalizations = 10

// BenchmarkNormalizeHostStrict_IDNRequestFanout approximates ONE proxied request
// to an internationalized domain: the strict dispatch gate plus the ~9 engines
// that each normalize the same A-label host. This is the number that matters for
// proxy throughput on IDN traffic.
func BenchmarkNormalizeHostStrict_IDNRequestFanout(b *testing.B) {
	const host = "xn--bcher-kva.example.com"
	benchIDNNorm, benchIDNOK = NormalizeHostStrict(host)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < perRequestNormalizations; j++ {
			benchIDNNorm, benchIDNOK = NormalizeHostStrict(host)
		}
	}
}

// BenchmarkNormalizeHostStrict_IDNRequestFanoutNoMemo is the same request,
// pre-change: every engine recomputes idna.ToASCII.
func BenchmarkNormalizeHostStrict_IDNRequestFanoutNoMemo(b *testing.B) {
	const host = "xn--bcher-kva.example.com"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < perRequestNormalizations; j++ {
			benchIDNNorm, benchIDNOK = normalizeHostStrictUncached(host)
		}
	}
}

// benchIDNParallelSink keeps parallel results alive without making every worker
// write a shared package-level variable, which would be a race under -race and
// would measure false sharing instead of lookup cost.
var benchIDNParallelSink atomic.Int64

// BenchmarkNormalizeHostStrict_IDNParallel is the concurrency benchmark: a warm
// memo is read-only, so lookups must scale across cores with no contention. Each
// worker folds into a goroutine-local total and publishes once on the way out.
func BenchmarkNormalizeHostStrict_IDNParallel(b *testing.B) {
	hosts := []string{
		"xn--bcher-kva.example.com", "bücher.example.com",
		"xn--fsq.com", "日本.example.com", "münchen.de",
	}
	for _, h := range hosts {
		NormalizeHostStrict(h) // warm
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local int64
		i := 0
		for pb.Next() {
			norm, ok := NormalizeHostStrict(hosts[i%len(hosts)])
			local += int64(len(norm))
			if ok {
				local++
			}
			i++
		}
		benchIDNParallelSink.Add(local)
	})
}

// BenchmarkNormalizeHostStrict_IDNThrash is the adversarial worst case: every
// lookup is a distinct host, so the memo misses and overwrites on every call.
// It must cost no more than the uncached path plus the slot write — the memo's
// fail-safe claim is that its degenerate case is today's behaviour, and this is
// where that is measured rather than asserted.
func BenchmarkNormalizeHostStrict_IDNThrash(b *testing.B) {
	hosts := make([]string, normMemoSlots*4)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("bücher%d.example.com", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchIDNNorm, benchIDNOK = NormalizeHostStrict(hosts[i%len(hosts)])
	}
}

// BenchmarkNormalizeHostStrict_IDNThrashNoMemo is the paired baseline for the
// thrash case: the SAME all-distinct host stream through the pre-change body,
// including the lowering the live path does, so the degenerate-case overhead the
// memo adds (one hash, one slot load, one key clone, one entry) is measured
// rather than inferred.
func BenchmarkNormalizeHostStrict_IDNThrashNoMemo(b *testing.B) {
	hosts := make([]string, normMemoSlots*4)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("bücher%d.example.com", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := strings.ToLower(strings.TrimSuffix(hosts[i%len(hosts)], "."))
		benchIDNNorm, benchIDNOK = normalizeHostStrictUncached(h)
	}
}

// BenchmarkNormalizeHostStrict_IDNColdFanout is the adversarial case as the
// REQUEST path actually presents it: a destination never seen before, normalized
// once per engine. The first call misses and pays the slow path plus the memo's
// insert; the other nine hit. This is the number that answers "what does a client
// that never repeats a host cost us now?" — the isolated-single-call thrash
// benchmark above is a floor on the overhead, not a shape this path produces,
// because the fan-out guarantees at least two lookups of the same host.
func BenchmarkNormalizeHostStrict_IDNColdFanout(b *testing.B) {
	hosts := make([]string, 4096)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("bücher%d.example.com", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hosts[i%len(hosts)]
		for j := 0; j < perRequestNormalizations; j++ {
			benchIDNNorm, benchIDNOK = NormalizeHostStrict(h)
		}
	}
}

// BenchmarkNormalizeHostStrict_IDNColdFanoutNoMemo is that request pre-change:
// all ten engines recompute idna.ToASCII.
func BenchmarkNormalizeHostStrict_IDNColdFanoutNoMemo(b *testing.B) {
	hosts := make([]string, 4096)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("bücher%d.example.com", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hosts[i%len(hosts)]
		for j := 0; j < perRequestNormalizations; j++ {
			lowered := strings.ToLower(strings.TrimSuffix(h, "."))
			benchIDNNorm, benchIDNOK = normalizeHostStrictUncached(lowered)
		}
	}
}
