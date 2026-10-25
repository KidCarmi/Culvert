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
	for i := range normMemoLong {
		normMemoLong[i].Store(nil)
	}
}

// normMemoOccupied counts filled slots across BOTH tiers — the memo's live
// entry count. Tests that need to know WHICH tier answered use
// normMemoOccupiedByTier.
func normMemoOccupied() int {
	main, long := normMemoOccupiedByTier()
	return main + long
}

// normMemoOccupiedByTier counts filled slots in the main and long tiers
// separately, so a test can assert that a shape landed in the tier its key
// length selects rather than merely landing somewhere.
func normMemoOccupiedByTier() (main, long int) {
	for i := range normMemo {
		if normMemo[i].Load() != nil {
			main++
		}
	}
	for i := range normMemoLong {
		if normMemoLong[i].Load() != nil {
			long++
		}
	}
	return main, long
}

// normMemoLiveEntries returns every live entry in both tiers, with the key
// bound that tier enforces, so an invariant can be asserted over the table as
// it actually stands rather than over the branch that maintains it.
func normMemoLiveEntries() []struct {
	entry     *normMemoEntry
	tier      string
	maxKeyLen int
} {
	var out []struct {
		entry     *normMemoEntry
		tier      string
		maxKeyLen int
	}
	for i := range normMemo {
		if e := normMemo[i].Load(); e != nil {
			out = append(out, struct {
				entry     *normMemoEntry
				tier      string
				maxKeyLen int
			}{e, "main", maxMemoHostLen})
		}
	}
	for i := range normMemoLong {
		if e := normMemoLong[i].Load(); e != nil {
			out = append(out, struct {
				entry     *normMemoEntry
				tier      string
				maxKeyLen int
			}{e, "long", maxMemoLongKeyLen})
		}
	}
	return out
}

// normMemoRetainedBytes is the bytes the table itself keeps alive: the slot
// array plus, for every live entry, the entry header and both of its strings.
// This is the figure the fixed-capacity design exists to bound.
func normMemoRetainedBytes() int {
	const slotPtr = 8   // atomic.Pointer
	const entryHdr = 40 // two string headers (16 each) + bool, padded
	total := (len(normMemo) + len(normMemoLong)) * slotPtr
	for _, live := range normMemoLiveEntries() {
		total += entryHdr + len(live.entry.host) + len(live.entry.norm)
	}
	return total
}

// normMemoCeilingBytes is the absolute footprint ceiling of both tiers: every
// slot filled with the longest key its tier admits and a maximum-length
// canonical value. It is a real ceiling only because every entry respects
// those bounds — asserted over the live table by
// TestIDNMemo_StoredEntriesRespectTheBound.
func normMemoCeilingBytes() int {
	const slotPtr = 8
	const entryHdr = 40
	return (len(normMemo)+len(normMemoLong))*slotPtr +
		normMemoSlots*(entryHdr+maxMemoHostLen+maxMemoHostLen) +
		normMemoLongSlots*(entryHdr+maxMemoLongKeyLen+maxMemoHostLen)
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
// TestIDNMemo_OversizeHostsAreNotRetained is unchanged by the long tier, and
// deliberately so: every case below canonicalizes to MORE than maxMemoHostLen
// (998, 995, 418 and 257 bytes respectively), so each is refused by the shared
// VALUE bound even when its key is short enough for a tier to consider it. Two
// of them — Unicode at 812 raw bytes and OneOverLimit at 257 — now reach the
// long tier's slot lookup rather than being rejected on key length alone, which
// is exactly why the value bound has to be the one doing this work.
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
			if len(wantNorm) <= maxMemoHostLen {
				t.Fatalf("probe host canonicalizes to %d bytes, inside the value bound — "+
					"this case no longer proves non-retention", len(wantNorm))
			}
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

// TestIDNMemo_PunycodeExpansionIsNotRetained is the MAIN-TIER gate for the
// value bound — the len(norm) check in normalizeHostStrictMemo.
//
// A host can breach the ceiling from either side: by arriving oversize (gated
// by TestIDNMemo_OversizeHostsAreNotRetained after CodeRabbit found that bound
// did not hold; its long-tier cases also reach the len(norm) check), or by
// arriving within the limit and EXPANDING past it through punycode. The second
// axis is the main tier's, and it had no gate of its own: a rewrite that kept
// the value bound for the long tier only would have passed every other test
// here. Measured with the main-tier check removed, the table retains 969 KB
// against its 554 KB main-tier ceiling, with a 668-byte norm in a slot — the
// same class of breach, and the same magnitude, as the oversize one.
//
// The gap was in the corpus, not the intent:
// TestIDNMemo_StoredEntriesRespectTheBound deliberately feeds "inputs whose
// punycode form is longer than their ASCII byte count suggests", but reaches
// for CJK, which COMPRESSES (a 252-byte CJK host measures 98 bytes as an
// A-label). Expansion needs one non-ASCII rune in each of many short labels.
//
// Each case must therefore be in-limit on the way in (so its key selects the
// main tier and the len(norm) check is the only thing standing between the
// host and a slot) and over the limit on the way out. Both preconditions are asserted,
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

			// Precondition 1: in-limit on the way in, so the key selects the
			// main tier and the long tier's handling cannot be what is tested.
			if len(lowered) > maxMemoHostLen {
				t.Fatalf("probe host is %d bytes, over the %d-byte limit — it "+
					"would key the long tier and this case proves nothing",
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
	// Every expanding host keys the main tier, so the long tier must stay
	// empty and the bound is the main tier's share of normMemoCeilingBytes:
	// every main slot filled with two maximum-length DNS names, plus the slot
	// pointers of both tiers that normMemoRetainedBytes always counts.
	if _, long := normMemoOccupiedByTier(); long != 0 {
		t.Fatalf("%d long-tier slot(s) filled by in-limit hosts — the expanding "+
			"shape no longer exercises the main tier", long)
	}
	ceiling := (len(normMemo)+len(normMemoLong))*8 + normMemoSlots*(40+2*maxMemoHostLen)
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
		// both normalize well inside the bound. Expansion needs one non-ASCII
		// rune per short label, so the real cases go in here — otherwise this
		// invariant holds vacuously on the main tier's expansion axis.
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
	corpus = append(corpus, longRawULabelHost(), beyondLongTierHost())
	for _, h := range corpus {
		NormalizeHostStrict(h)
	}
	for _, live := range normMemoLiveEntries() {
		e := live.entry
		if len(e.host) > live.maxKeyLen {
			t.Fatalf("%s tier holds len(host)=%d, its key bound is %d",
				live.tier, len(e.host), live.maxKeyLen)
		}
		// The VALUE bound is maxMemoHostLen in BOTH tiers: a canonical form
		// longer than the DNS limit is refused by the dispatch gates, so
		// retaining one would loosen the ceiling and buy nothing.
		if len(e.norm) > maxMemoHostLen {
			t.Fatalf("%s tier holds len(norm)=%d, the value bound is %d",
				live.tier, len(e.norm), maxMemoHostLen)
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
	// Absolute ceiling: every slot of both tiers filled with the longest key it
	// admits and a maximum-length canonical value. It is a real ceiling only
	// because every entry respects those bounds — asserted over the live table
	// by TestIDNMemo_StoredEntriesRespectTheBound and at the boundaries by
	// TestIDNMemo_OversizeHostsAreNotRetained and
	// TestIDNMemo_BeyondLongTierIsNormalizedButNotRetained.
	ceiling := normMemoCeilingBytes()
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

// ── The long tier: raw over the DNS limit, canonical inside it ──────────────
//
// This is the shape the first version of maxMemoHostLen's rationale said could
// not exist. IDNA SHRINKS a U-label authority, so a host whose RAW spelling is
// well past the 253-byte DNS limit can canonicalize comfortably inside it —
// proxy_host_bounds.go records the worst legitimate case as 883 raw bytes
// collapsing to a 251-byte A-label, which is why the raw pre-cap is 1 KiB. Such
// a host is ACCEPTED by both proxy dispatch gates, so it walks the full ~10x
// per-request normalization fan-out, and a key bound measured on the raw
// spelling excluded every one of them from the memo.

// longRawULabelHost builds that shape, and builds it RESOLVABLE rather than
// merely accepted: eight U-labels of 20 CJK code points each, so every
// canonical label lands at 26 bytes — inside the 63-byte A-label limit of
// RFC 1035 §2.3.1 — for 499 raw bytes against 227 canonical.
func longRawULabelHost() string {
	label := strings.Repeat("日", 20)
	return strings.TrimSuffix(strings.Repeat(label+".", 8), ".") + ".example.com"
}

// oneOverPrefix and oneOverSuffix are the literals the boundary case is built
// from, named so the repetition can be computed from their real lengths.
const (
	oneOverPrefix = "xn--bcher-kva."
	oneOverSuffix = ".de"
)

// TestIDNMemo_KeyBoundCoversTheRequestRawCap is this package's half of the
// two-sided proof that the memo can key on every authority a dispatch gate
// admits.
//
// The root TestHostutilLongRawULabelReachesTheMemo owns the other half, and on
// its own it is not enough: it can only MIRROR maxMemoLongKeyLen, because that
// constant is package-private here, and a mirrored literal does not move when
// the real constant does. So if this bound were lowered to 900, that test would
// still compare 1024 against the proxy cap and still pass, and its 499-byte
// probe would still fit — the asymmetry would come back silently (CodeRabbit on
// PR #1624, verified and correct; the claim that the mirror could only ever fail
// in the safe direction was wrong).
//
// Each half therefore asserts the side whose real constant its own package
// owns:
//
//	here:  maxMemoLongKeyLen        >= mirrored raw cap (1024)
//	root:  mirrored memo bound      >= maxRawDestAuthorityBytes
//
// Together they give maxMemoLongKeyLen >= maxRawDestAuthorityBytes, and moving
// either real constant fails one of them.
func TestIDNMemo_KeyBoundCoversTheRequestRawCap(t *testing.T) {
	// maxRawDestAuthorityBytes in proxy_host_bounds.go, which this package
	// cannot import. The root half pins this number against the real one.
	const mirroredRawDestAuthorityBytes = 1024

	if maxMemoLongKeyLen < mirroredRawDestAuthorityBytes {
		t.Errorf("REGRESSION: the request path admits raw authorities up to %d bytes but the "+
			"memo keys on at most %d, leaving a %d-byte band of ACCEPTED destinations that can "+
			"never be memoized — every request to one pays the full un-memoized IDNA fan-out",
			mirroredRawDestAuthorityBytes, maxMemoLongKeyLen,
			mirroredRawDestAuthorityBytes-maxMemoLongKeyLen)
	}
	// The value bound is the DNS limit by definition, not a tunable: a canonical
	// form longer than it is refused by the canonical gate.
	if maxMemoHostLen != 253 {
		t.Errorf("maxMemoHostLen is %d; the value bound is the 253-byte DNS name maximum",
			maxMemoHostLen)
	}
}

// TestIDNMemo_TierMasksMatchTheirTables pins the pairing normMemoTableFor
// returns: a mask that did not match its tier's length would silently fold the
// tier into a fraction of its slots (mask too small) or index out of range
// (mask too large).
func TestIDNMemo_TierMasksMatchTheirTables(t *testing.T) {
	cases := []struct {
		tier string
		// slots is uint64, not int, so comparing it with the mask needs no
		// conversion. The literals below are untyped constants, so they become
		// uint64 at compile time; an int field would put a runtime
		// int->uint64 conversion here and gosec reports that as G115 — which
		// is what the production code this test guards was just fixed for, so
		// reintroducing it in the guard itself would be an odd way to pass.
		slots uint64
		mask  uint64
	}{
		{"main", normMemoSlots, normMemoMask},
		{"long", normMemoLongSlots, normMemoLongMask},
	}
	for _, c := range cases {
		if c.slots&(c.slots-1) != 0 {
			t.Errorf("%s tier has %d slots, not a power of two — a mask cannot index it",
				c.tier, c.slots)
		}
		if want := c.slots - 1; c.mask != want {
			t.Errorf("%s tier mask is %d, want %d for %d slots", c.tier, c.mask, want, c.slots)
		}
	}
	// And the masks the lookup actually receives are those, for a key of each
	// tier's length class.
	if _, mask := normMemoTableFor(strings.Repeat("a", maxMemoHostLen)); mask != normMemoMask {
		t.Errorf("a main-tier key selected mask %d, want %d", mask, normMemoMask)
	}
	if _, mask := normMemoTableFor(strings.Repeat("a", maxMemoHostLen+1)); mask != normMemoLongMask {
		t.Errorf("a long-tier key selected mask %d, want %d", mask, normMemoLongMask)
	}
	if table, mask := normMemoTableFor(strings.Repeat("a", maxMemoLongKeyLen+1)); table != nil || mask != 0 {
		t.Errorf("a key past both bounds selected a tier (mask %d), want none", mask)
	}
}

// beyondLongTierHost is past the long tier's key bound, so no tier may retain
// it. maxMemoLongKeyLen clears the empirical maximum IDN expansion, so nothing
// this long can canonicalize inside the DNS limit anyway.
func beyondLongTierHost() string {
	return strings.Repeat("日", 400) + ".example.com"
}

// TestIDNMemo_LongRawULabelHostIsAcceptedAndRetained is the regression gate for
// the gap. It proves the premise before it asserts the fix: the probe host is a
// DNS-valid name, both dispatch-gate predicates admit it, and its raw spelling
// is over the main tier's key bound. Only then does it require that the memo
// retain it — in the long tier, leaving the main tier untouched.
//
// Verified failing against the pre-fix body, where the final assertion reported
// 0 occupied slots.
func TestIDNMemo_LongRawULabelHostIsAcceptedAndRetained(t *testing.T) {
	// The two dispatch-gate bounds, mirrored from proxy_host_bounds.go. This
	// package cannot import package main, so they are restated; the root
	// TestHostutilLongRawULabelReachesTheMemo pins the agreement.
	const maxRawDestAuthorityBytes = 1024 // rawAuthorityOversize
	const maxDestHostLen = 253            // canonicalHostOversize

	host := longRawULabelHost()
	norm, ok := NormalizeHostStrict(host)
	if !ok {
		t.Fatalf("probe host does not canonicalize; the shape proves nothing")
	}

	// ── Premise 1: the raw spelling is past the main tier's key bound ───────
	if len(host) <= maxMemoHostLen {
		t.Fatalf("probe host is %d raw bytes, inside the main tier at %d — "+
			"the case no longer exercises the long tier", len(host), maxMemoHostLen)
	}
	if len(host) > maxMemoLongKeyLen {
		t.Fatalf("REGRESSION: a %d-byte raw authority that BOTH dispatch gates accept "+
			"(canonical %d bytes, longest label 26) exceeds the memo's key bound of %d, so no tier "+
			"may retain it and every request to it pays the full un-memoized IDNA fan-out "+
			"(~53 µs and 180 allocations across the per-request fan-out)",
			len(host), len(norm), maxMemoLongKeyLen)
	}

	// ── Premise 2: both dispatch gates ACCEPT it, so the fan-out is real ───
	if len(host) > maxRawDestAuthorityBytes {
		t.Fatalf("raw gate would refuse %d bytes; the fan-out is unreachable", len(host))
	}
	if len(norm) > maxDestHostLen {
		t.Fatalf("canonical gate would refuse %d bytes; the fan-out is unreachable", len(norm))
	}

	// ── Premise 3: it is a resolvable name, not just an accepted string ─────
	for _, label := range strings.Split(norm, ".") {
		if len(label) > 63 {
			t.Fatalf("canonical label %q is %d bytes, over the RFC 1035 limit of 63 — "+
				"the shape is not a legitimate destination", label, len(label))
		}
	}

	// ── The answer is unchanged: this is about retention only ──────────────
	wantNorm, wantOK := normalizeHostStrictUncached(strings.ToLower(strings.TrimSuffix(host, ".")))
	normMemoResetForTest()
	for round := 0; round < 3; round++ {
		gotNorm, gotOK := NormalizeHostStrict(host)
		if gotNorm != wantNorm || gotOK != wantOK {
			t.Fatalf("round %d: got (%q…, %v), uncached (%q…, %v)",
				round, truncForLog(gotNorm), gotOK, truncForLog(wantNorm), wantOK)
		}
	}

	// ── The fix: retained, in the long tier, and nowhere else ──────────────
	main, long := normMemoOccupiedByTier()
	if long != 1 {
		t.Errorf("REGRESSION: %d long-tier slots filled for a %d-byte raw / %d-byte canonical "+
			"host that both dispatch gates accept — it must be memoized, or every request to it "+
			"pays the full un-memoized fan-out", long, len(host), len(norm))
	}
	if main != 0 {
		t.Errorf("%d main-tier slots filled; a long key must not consume main-tier capacity", main)
	}
	t.Logf("raw=%d canonical=%d longest label=%d: main=%d long=%d",
		len(host), len(norm), 26, main, long)
}

// TestIDNMemo_LongTierHitIsAllocationFree pins the point of the tier: a warm
// long-tier lookup must cost no allocation, like a main-tier hit. The slice
// header normMemoTableFor returns is stack-allocated; if that ever stops being
// true, the long tier would add a heap allocation to the very path it exists to
// make cheaper.
func TestIDNMemo_LongTierHitIsAllocationFree(t *testing.T) {
	host := longRawULabelHost()
	normMemoResetForTest()
	NormalizeHostStrict(host) // warm the slot

	if allocs := testing.AllocsPerRun(200, func() {
		benchIDNNorm, benchIDNOK = NormalizeHostStrict(host)
	}); allocs != 0 {
		t.Errorf("warm long-tier hit allocates %.2f times per call, want 0", allocs)
	}
}

// TestIDNMemo_BeyondLongTierIsNormalizedButNotRetained is the outer boundary:
// past maxMemoLongKeyLen no tier may retain, the answer is still identical to
// the uncached body, and the table stays empty. This is what keeps the ceiling
// a bound rather than an expectation now that two tiers exist.
func TestIDNMemo_BeyondLongTierIsNormalizedButNotRetained(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"Unicode", beyondLongTierHost()},
		// One byte over the long tier's key bound — the boundary itself. The
		// repetition is computed from BOTH literals, so the host is exactly
		// maxMemoLongKeyLen+1 bytes and stays that way if either literal
		// changes; subtracting a hand-counted constant is how the first version
		// of this case silently became 1028 bytes, proving non-retention but
		// not the boundary it is named for (CodeRabbit on PR #1624).
		{"OneOverLongBound", oneOverPrefix +
			strings.Repeat("c", maxMemoLongKeyLen+1-len(oneOverPrefix)-len(oneOverSuffix)) +
			oneOverSuffix},
		// An ACE label, so it reaches the slow path rather than the
		// already-canonical fast path, on an authority past the raw gate
		// entirely — what a non-request caller (feed parsing, admin patterns)
		// can still hand this function.
		{"ValidACEPastRawCap", "xn--bcher-kva." + strings.Repeat("a", 1200) + ".com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			normMemoResetForTest()
			lowered := strings.ToLower(strings.TrimSuffix(c.host, "."))
			if len(lowered) <= maxMemoLongKeyLen {
				t.Fatalf("probe host is %d bytes, inside the long tier at %d — "+
					"the case proves nothing", len(lowered), maxMemoLongKeyLen)
			}
			if c.name == "OneOverLongBound" && len(lowered) != maxMemoLongKeyLen+1 {
				t.Fatalf("the boundary case is %d bytes, not exactly one over %d — "+
					"it no longer tests the boundary it is named for",
					len(lowered), maxMemoLongKeyLen)
			}
			wantNorm, wantOK := normalizeHostStrictUncached(lowered)
			for round := 0; round < 3; round++ {
				gotNorm, gotOK := NormalizeHostStrict(c.host)
				if gotNorm != wantNorm || gotOK != wantOK {
					t.Fatalf("round %d: got (%q…, %v), uncached (%q…, %v)",
						round, truncForLog(gotNorm), gotOK, truncForLog(wantNorm), wantOK)
				}
			}
			if n := normMemoOccupied(); n != 0 {
				t.Errorf("REGRESSION: %d slots filled by a %d-byte host — past the long tier's "+
					"key bound nothing may be retained, or the footprint ceiling does not hold",
					n, len(lowered))
			}
		})
	}
}

// TestIDNMemo_LongTierBoundedFootprint is the long tier's own memory test. Its
// key is a client-chosen authority just as the main tier's is, and its entries
// are up to maxMemoLongKeyLen bytes, so it must not grow with the number of
// distinct long hosts seen. Feeding it 64x more than it has slots must leave
// both the slot count and the retained bytes inside the fixed ceiling.
func TestIDNMemo_LongTierBoundedFootprint(t *testing.T) {
	normMemoResetForTest()
	label := strings.Repeat("日", 20)
	prefix := strings.Repeat(label+".", 8)
	const distinct = normMemoLongSlots * 64
	for i := 0; i < distinct; i++ {
		host := prefix + fmt.Sprintf("x%d.example.com", i)
		if len(host) <= maxMemoHostLen || len(host) > maxMemoLongKeyLen {
			t.Fatalf("generated host %d is %d bytes, not a long-tier key", i, len(host))
		}
		NormalizeHostStrict(host)
	}
	main, long := normMemoOccupiedByTier()
	if long > normMemoLongSlots {
		t.Fatalf("long tier holds %d entries after %d distinct hosts, ceiling %d",
			long, distinct, normMemoLongSlots)
	}
	if retained, ceiling := normMemoRetainedBytes(), normMemoCeilingBytes(); retained > ceiling {
		t.Fatalf("memo retains %d B after %d distinct long hosts, ceiling %d B",
			retained, distinct, ceiling)
	}
	t.Logf("after %d distinct long-raw IDN hosts: main=%d long=%d/%d, %d B retained (ceiling %d B)",
		distinct, main, long, normMemoLongSlots, normMemoRetainedBytes(), normMemoCeilingBytes())
}

// TestIDNMemo_LongTierConcurrentStress is the long tier's race gate: the same
// immutable-entry / single-atomic-store contract as the main tier, exercised
// over a host set far larger than the tier under continuous eviction. Run under
// -race. Every answer must still equal the uncached body's.
func TestIDNMemo_LongTierConcurrentStress(t *testing.T) {
	normMemoResetForTest()
	label := strings.Repeat("日", 20)
	prefix := strings.Repeat(label+".", 8)
	hosts := make([]string, normMemoLongSlots*4)
	want := make([]string, len(hosts))
	for i := range hosts {
		hosts[i] = prefix + fmt.Sprintf("x%d.example.com", i)
		want[i], _ = normalizeHostStrictUncached(hosts[i])
	}

	var wg sync.WaitGroup
	var mismatches atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < 40; round++ {
				for i := range hosts {
					j := (i + g) % len(hosts)
					got, ok := NormalizeHostStrict(hosts[j])
					if !ok || got != want[j] {
						mismatches.Add(1)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if n := mismatches.Load(); n != 0 {
		t.Fatalf("%d crossed or wrong answers under concurrent long-tier eviction", n)
	}
	if _, long := normMemoOccupiedByTier(); long > normMemoLongSlots {
		t.Fatalf("long tier grew to %d entries under stress, ceiling %d", long, normMemoLongSlots)
	}
}

// BenchmarkIDNLongRawFanout and BenchmarkIDNLongRawFanoutNoMemo are the
// measurement behind the tier: the ~10x per-request fan-out for ONE accepted
// long-raw U-label destination, through the current body and through the
// pre-fix body. Both include the strings.ToLower pass, so they are directly
// comparable (Xeon @2.80GHz, go1.26.9, -count=2):
//
//	per 10x fan-out            pre-fix                  long tier
//	long-raw U-label      85 000-94 000 ns  200     27 000-29 000 ns  0
//
// The ~28 µs that remain are strings.ToLower's per-rune Map walk, which runs
// ahead of the memo and is not memoizable — see the residual note under
// maxMemoHostLen. The in-limit U-label rows for the same fan-out are ~7 400 ns /
// 70 allocs and ~424 ns / 0 allocs (BenchmarkNormalizeHostStrict_IDNRequestFanout).
func BenchmarkIDNLongRawFanout(b *testing.B) {
	host := longRawULabelHost()
	normMemoResetForTest()
	NormalizeHostStrict(host)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10; j++ {
			benchIDNNorm, benchIDNOK = NormalizeHostStrict(host)
		}
	}
}

// BenchmarkIDNLongRawFanoutNoMemo is the same fan-out through the pre-fix body:
// NormalizeHostStrict's lowering pass and then the frozen uncached slow path,
// which is exactly what every request to such a destination used to pay. The
// lowering is INSIDE the loop deliberately — leaving it out measures a path the
// request never takes and understates the pre-fix cost by ~28 µs.
func BenchmarkIDNLongRawFanoutNoMemo(b *testing.B) {
	host := longRawULabelHost()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10; j++ {
			lowered := strings.ToLower(strings.TrimSuffix(host, "."))
			benchIDNNorm, benchIDNOK = normalizeHostStrictUncached(lowered)
		}
	}
}

// TestIDNMemo_LongTierDoesNotRetainFailures pins the one asymmetry between the
// tiers: a FAILED normalization is memoized in the main tier and not in the
// long tier.
//
// It is not a micro-optimization. Both dispatch gates refuse an unnormalizable
// host whose bare form exceeds maxDestHostLen immediately — HTTP via
// rejectOversizeUnnormalizableHost, ahead of the connection limiter, the rate
// limiter, Stage-1 auth and every matcher; SOCKS5 at the normalization point —
// so there is exactly one normalization and no fan-out for a hit to collapse.
// Storing one would clone up to maxMemoLongKeyLen bytes of attacker-chosen key
// and allocate an entry on every UNIQUE malformed long authority, for nothing.
//
// The short case is the control, and it must keep its entry: a short
// unnormalizable host passes the oversize gate and reaches Stage-1
// authentication's category fusion before the RISK-013 refusal, which does
// normalize repeatedly.
//
// Found by Codex review on PR #1624. Verified failing against the pre-fix body,
// which retained the long malformed key.
func TestIDNMemo_LongTierDoesNotRetainFailures(t *testing.T) {
	// Malformed ACE label, so normalization FAILS, on an authority inside the
	// long tier's key bound and past the main tier's.
	long := "xn--$$$." + strings.Repeat("a", 900) + ".com"
	if len(long) <= maxMemoHostLen || len(long) > maxMemoLongKeyLen {
		t.Fatalf("probe is %d bytes, not a long-tier key", len(long))
	}

	normMemoResetForTest()
	wantNorm, wantOK := normalizeHostStrictUncached(long)
	if wantOK {
		t.Fatalf("probe host normalizes successfully; the case needs a FAILING host")
	}
	// The answer is unchanged — this is about retention only.
	for round := 0; round < 3; round++ {
		gotNorm, gotOK := NormalizeHostStrict(long)
		if gotNorm != wantNorm || gotOK != wantOK {
			t.Fatalf("round %d: got (%q, %v), uncached (%q, %v)", round, gotNorm, gotOK, wantNorm, wantOK)
		}
	}
	if main, lng := normMemoOccupiedByTier(); main != 0 || lng != 0 {
		t.Errorf("REGRESSION: a %d-byte unnormalizable authority filled main=%d long=%d slots. "+
			"Both dispatch gates refuse it immediately, ahead of every matcher, so there is no "+
			"fan-out for a hit to collapse — retaining it clones the whole attacker-chosen key "+
			"for nothing on every unique such request", len(long), main, lng)
	}

	// ── Control: a SHORT failure is still memoized ─────────────────────────
	// It reaches Stage-1 auth's matchers before the RISK-013 refusal, so the
	// repeat is real and the negative entry pays for itself.
	normMemoResetForTest()
	// "xn--.com" is NOT a failing host — the zero-option profile accepts an
	// empty ACE payload. hostutil_test.go's own fail-closed table supplies one.
	const short = "xn--$$$.com"
	if len(short) > maxMemoHostLen {
		t.Fatalf("control host is %d bytes, not a main-tier key", len(short))
	}
	if _, ok := NormalizeHostStrict(short); ok {
		t.Fatalf("control host normalizes successfully; it must FAIL to be the control")
	}
	if main, lng := normMemoOccupiedByTier(); main != 1 || lng != 0 {
		t.Errorf("a short unnormalizable host filled main=%d long=%d, want main=1 long=0: "+
			"the main tier must keep memoizing failures, or every request to a malformed "+
			"short host re-pays idna.ToASCII across the auth-matcher fan-out", main, lng)
	}
}
