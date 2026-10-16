package hostutil

import (
	"fmt"
	"hash/maphash"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// Security-regression gates for the memoized IDNA slow path (idnamemo.go),
// covering BOTH retention tiers.
//
// idnamemo_test.go proves the memo is fast, bounded and differentially correct
// over the shapes it retains. The two gates here cover properties whose failure
// mode is a security one rather than a performance one, and which that file
// does not pin:
//
//  1. A memo must never upgrade a REJECTION to an acceptance. NormalizeHostStrict
//     is the fail-closed gate the request path uses so a host that cannot be
//     canonicalized is refused instead of flowing un-normalized into FQDN,
//     blocklist and category matching (RISK-013). A direct-mapped slot is shared
//     by design, so the crossing that matters is rejected-host-meets-accepted-
//     entry; the existing collision test alternates two ACCEPTED hosts and
//     therefore cannot see it.
//
//  2. The stored key must be a CLONE, never the caller's string. The key arrives
//     as a substring of whatever buffer the caller holds — on the request path,
//     net/http's header buffer — so an entry that kept it would pin that whole
//     backing array per slot and the bounded-footprint property would be a
//     measurement of the test corpus rather than a bound.
//
// Ported from the closed PR #1617, which gated the single-tier memo, and
// adapted to the long tier this change adds. #1617's third gate asserted that a
// legitimate long-raw IDN is NOT retained; that is the gap the long tier closes,
// so it is deliberately not ported — TestIDNMemo_LongRawULabelHostIsAcceptedAndRetained
// asserts the opposite.

// normMemoSlotForTest returns the slot host would occupy in the tier its key
// length selects, or nil when no tier may retain it. It mirrors the lookup in
// normalizeHostStrictMemo, so a test can find an entry again after the caller's
// string is gone.
func normMemoSlotForTest(host string) *atomic.Pointer[normMemoEntry] {
	table, mask := normMemoTableFor(host)
	if table == nil {
		return nil
	}
	return &table[maphash.String(normMemoSeed, host)&mask]
}

// normMemoSlotIndexForTest is the tier-local slot index plus the tier itself,
// so two hosts are only reported as sharing a slot when they share the TABLE
// too (main-tier slot 7 and long-tier slot 7 are different slots).
func normMemoSlotIndexForTest(host string) (tier int, slot uint64) {
	table, mask := normMemoTableFor(host)
	switch {
	case table == nil:
		return -1, 0
	case len(table) == normMemoSlots:
		tier = 0
	default:
		tier = 1
	}
	return tier, maphash.String(normMemoSeed, host) & mask
}

// crossVerdictFamily is one tier's pair of slow-path host generators. Both
// reach the memo: the accepted family is non-ASCII, the rejected one carries an
// ACE label, so neither is answered by the already-canonical fast path. The
// rejected family is malformed Punycode, which is exactly what the fail-closed
// gate exists to refuse.
type crossVerdictFamily struct {
	name     string
	accepted func(i int) string
	rejected func(i int) string
}

// longTierLabelPrefix is eight 20-rune CJK U-labels — the shape of
// longRawULabelHost, whose canonical labels sit inside the 63-byte limit — so a
// host built on it is past the main tier's key bound and inside the long tier's.
var longTierLabelPrefix = strings.Repeat(strings.Repeat("日", 20)+".", 8)

var crossVerdictFamilies = []crossVerdictFamily{
	{
		name:     "MainTier",
		accepted: func(i int) string { return fmt.Sprintf("bücher%d.example.com", i) },
		rejected: func(i int) string { return fmt.Sprintf("xn--%d.example.com", i) },
	},
	{
		name:     "LongTier",
		accepted: func(i int) string { return longTierLabelPrefix + fmt.Sprintf("x%d.example.com", i) },
		// A malformed ACE label on an authority inside the long tier's key
		// bound: what a client can hand the HTTP raw gate (1 KiB) unrefused.
		rejected: func(i int) string { return fmt.Sprintf("xn--%d.", i) + strings.Repeat("a", 300) + ".com" },
	},
}

// findCrossVerdictCollision searches for an ACCEPTED and a REJECTED slow-path
// host of one family that land in the same direct-mapped slot of the same tier
// under this process's seed. The seed is randomized per process, so the pair is
// found at runtime.
func findCrossVerdictCollision(f crossVerdictFamily, budget int) (accepted, rejected string, found bool) {
	type key struct {
		tier int
		slot uint64
	}
	bySlot := make(map[key]string, budget)
	for i := 0; i < budget; i++ {
		h := f.accepted(i)
		tier, slot := normMemoSlotIndexForTest(h)
		bySlot[key{tier, slot}] = h
	}
	for i := 0; i < budget; i++ {
		h := f.rejected(i)
		tier, slot := normMemoSlotIndexForTest(h)
		if a, ok := bySlot[key{tier, slot}]; ok {
			return a, h, true
		}
	}
	return "", "", false
}

// TestIDNMemo_RejectionIsNeverUpgradedToAcceptance is the fail-closed gate.
//
// NormalizeHostStrict's contract is that ok=false means REFUSE the request
// (RISK-013): a host the normalizer cannot map to canonical ASCII must not reach
// FQDN/blocklist/category matching un-normalized, because a fail-open in the
// canonicalization step is the asymmetry evasion techniques target. A memo bug
// that answered a rejected host from a neighbouring accepted entry would convert
// that fail-closed gate into a fail-OPEN one, silently, for a host an attacker
// chooses — so the crossing is tested in BOTH directions, with each host finding
// the other resident in their shared slot, in each tier.
//
// The long tier never RETAINS a rejection (TestIDNMemo_LongTierDoesNotRetainFailures),
// so there the accepted host is resident on every rejected lookup — which makes
// the security-primary direction (a rejection answered from a resident
// acceptance) the one exercised on every round, not merely on alternate ones.
//
// TestIDNMemo_CollisionAnswersBothHosts covers the same mechanism with two
// accepted hosts; it cannot observe the verdict crossing, which is the half with
// a security consequence.
func TestIDNMemo_RejectionIsNeverUpgradedToAcceptance(t *testing.T) {
	for _, f := range crossVerdictFamilies {
		t.Run(f.name, func(t *testing.T) {
			accepted, rejected, wantNorm, ok := resolveCrossVerdictPair(t, f)
			if !ok {
				return // resolveCrossVerdictPair already skipped this family
			}
			// Alternate so that each lookup finds the OTHER verdict resident in
			// the slot (where the tier retains it), then repeat — a
			// direct-mapped slot is overwritten on every retained miss, so the
			// crossing is retried from both residencies. The ACCEPTED host goes
			// first in each round, which is what makes the security-primary
			// direction a deterministic probe rather than one that depends on
			// which host happened to occupy the slot.
			for round := 0; round < 4; round++ {
				assertCrossingHolds(t, round, accepted, rejected, wantNorm)
			}
			assertRejectionSurvivesRepeat(t, rejected)
		})
	}
}

// resolveCrossVerdictPair finds the colliding pair for one family and checks
// every precondition the crossing assertions rest on: the accepted host really
// normalizes, the rejected one really does not, and the two really share a
// slot. ok=false means it has already called t.Skip, so the caller returns.
//
// Split out of the test above to keep each function inside the repository's
// gocognit budget (30; the combined body measured 39), and because the
// preconditions are a separate claim from the crossing itself — if one of them
// stops holding, the failure should name the setup rather than the invariant.
func resolveCrossVerdictPair(t *testing.T, f crossVerdictFamily) (accepted, rejected, wantNorm string, ok bool) {
	t.Helper()
	normMemoResetForTest()
	accepted, rejected, found := findCrossVerdictCollision(f, 1<<13)
	if !found {
		t.Skip("no accepted/rejected pair collided within the search budget (seed-dependent)")
		return "", "", "", false
	}
	wantNorm, wantOK := normalizeHostStrictUncached(accepted)
	if !wantOK {
		t.Fatalf("probe host %q was expected to normalize; the case proves nothing", truncForLog(accepted))
	}
	if _, rejectedOK := normalizeHostStrictUncached(rejected); rejectedOK {
		t.Fatalf("probe host %q was expected to be REJECTED; the case proves nothing", truncForLog(rejected))
	}
	if normMemoSlotForTest(accepted) != normMemoSlotForTest(rejected) {
		t.Fatalf("probe hosts do not share a slot; the case proves nothing")
	}
	return accepted, rejected, wantNorm, true
}

// assertCrossingHolds is one round of the crossing: the accepted host answers
// correctly and becomes resident, and the rejected host that shares its slot is
// still refused with the acceptance sitting right there.
func assertCrossingHolds(t *testing.T, round int, accepted, rejected, wantNorm string) {
	t.Helper()
	if norm, ok := NormalizeHostStrict(accepted); norm != wantNorm || !ok {
		t.Fatalf("REGRESSION (round %d): NormalizeHostStrict(%q…) = (%q…, %v), want (%q…, true) — "+
			"a valid host was refused from a colliding rejection entry",
			round, truncForLog(accepted), truncForLog(norm), ok, truncForLog(wantNorm))
	}
	if e := normMemoSlotForTest(accepted).Load(); e == nil || e.host != accepted {
		t.Fatalf("round %d: the accepted host is not resident after its lookup; "+
			"the crossing below would not be exercised", round)
	}
	if norm, ok := NormalizeHostStrict(rejected); ok || norm != "" {
		t.Fatalf("REGRESSION (round %d): NormalizeHostStrict(%q…) = (%q…, %v), want (\"\", false) — "+
			"a host that cannot be canonicalized was ACCEPTED from a colliding entry, turning the "+
			"fail-closed dispatch gate into a fail-open one (RISK-013)",
			round, truncForLog(rejected), truncForLog(norm), ok)
	}
}

// assertRejectionSurvivesRepeat requires the rejection to stay a rejection on
// consecutive lookups with no intervening eviction: a HIT on the memoized
// rejection in the main tier, a recomputation beside the resident acceptance in
// the long tier (which does not retain failures).
func assertRejectionSurvivesRepeat(t *testing.T, rejected string) {
	t.Helper()
	for round := 0; round < 2; round++ {
		if norm, ok := NormalizeHostStrict(rejected); ok || norm != "" {
			t.Fatalf("REGRESSION: a rejection was answered as (%q…, %v) on repeat %d",
				truncForLog(norm), ok, round)
		}
	}
}

// TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer pins the clone in
// normalizeHostStrictMemo, which the bounded-footprint property depends on, in
// both tiers.
//
// The key reaches the memo as a SUBSTRING of whatever the caller passed —
// strings.ToLower returns its input unchanged when there is nothing to lower
// (strings.Map does the same for a non-ASCII input with nothing to map) and
// strings.TrimSuffix returns a substring — and on the request path that input
// is a slice of net/http's header buffer. An entry that kept it would pin the
// whole backing array for the life of the entry: across both tiers that is
// gigabytes held alive by hosts whose own length accounting (len(e.host))
// reports at most a kilobyte each, so the footprint tests would still pass
// while the process retained the buffers. The long tier makes this sharper, not
// weaker: its keys are up to 1 KiB of client-chosen bytes, so it is the tier
// where a lazy "the key is already bounded, skip the clone" would be tempting.
//
// That is why the assertion is on RETENTION rather than on size: the test drops
// every reference it holds to a large buffer the probe host was sliced out of,
// then asks the collector how much is still reachable. A cloned key lets the
// buffer go; an aliased one cannot. The margin is three orders of magnitude
// (aliased retains >= aliasProbePadding, cloned retains at most a couple of
// kilobytes), so the threshold is nowhere near GC or allocator noise.
//
// Pointer identity via unsafe.StringData would say the same thing in one
// comparison, and this file deliberately does not use it: internal/hostutil is
// on the request path, internal/blocklist's shard test records the house rule
// that a security-critical package does not import unsafe, and gosec's G103
// would need a suppression on every call site. Retention is the property that
// actually matters here anyway — aliasing is only a defect because of what it
// keeps alive.
func TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
		tier   int // 0 main, 1 long
	}{
		{"MainTier", "bücher-alias.example.com", 0},
		{"LongTier", longTierLabelPrefix + "alias.example.com", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if tier, _ := normMemoSlotIndexForTest(c.suffix); tier != c.tier {
				t.Fatalf("probe host is %d bytes and selects tier %d, want tier %d — the case is built wrong",
					len(c.suffix), tier, c.tier)
			}
			assertKeyDoesNotAliasCallerBuffer(t, c.suffix)
		})
	}
}

func assertKeyDoesNotAliasCallerBuffer(t *testing.T, suffix string) {
	t.Helper()
	normMemoResetForTest()
	runtime.GC()
	runtime.GC() // the first cycle may leave the previous one's garbage unswept
	baseline := heapAllocBytes()

	// probe is an independent copy of the host, kept only so the slot can be
	// found again once the padded buffer is unreachable. At most ~1 KiB, it
	// retains nothing of consequence.
	var probe string

	// The substring and the value the memo returned both live ONLY inside this
	// call. Nothing is reassigned to drop them: they go out of scope when it
	// returns, which the language guarantees and no linter can mistake for a
	// wasted write. norm matters as much as the key — every caller keys a store,
	// a log line or a policy decision on it and outlives the call, so it must
	// not alias the caller's buffer either.
	e := func() *normMemoEntry {
		host := aliasProbeHost(suffix)
		probe = strings.Clone(host)
		norm, ok := NormalizeHostStrict(host)
		if !ok {
			t.Fatalf("NormalizeHostStrict(%q…) rejected a valid IDN host", truncForLog(probe))
		}
		if norm == "" {
			t.Fatalf("NormalizeHostStrict(%q…) returned an empty host with ok=true", truncForLog(probe))
		}
		return normMemoSlotForTest(probe).Load()
	}()
	if e == nil || e.host != probe {
		t.Fatalf("the probe host was not retained (entry present: %v); the case proves nothing", e != nil)
	}
	if len(e.host) >= aliasProbePadding {
		t.Fatalf("the entry's key is %d bytes; the probe is built wrong", len(e.host))
	}

	runtime.GC()
	runtime.GC()
	after := heapAllocBytes()

	// A cloned key retains the entry and its two strings. An aliased one
	// retains the whole padded buffer, so anything approaching it is the defect.
	//
	// The predicate is `after > baseline+ceiling` rather than a
	// `retained := after - baseline` subtraction, and that is not a style
	// preference. Both are uint64, and HeapAlloc can legitimately read BELOW the
	// baseline: garbage that was still live when the baseline was taken may be
	// swept afterwards, and other goroutines free memory between the two reads.
	// With a cloned key the margin is a few hundred bytes, i.e. the measurement
	// sits ON that boundary rather than near it, so one byte of downward drift
	// would wrap the subtraction to ~2^64, clear this ceiling, and report a
	// FALSE "REGRESSION" — most readily in the -shuffle=on lane, where the test
	// that ran before this one varies (CodeRabbit, PR #1617).
	//
	// Comparing against baseline+ceiling needs no clamp: a reading at or below
	// the baseline means nothing was retained, which is the passing answer, and
	// the branch can only be entered when after exceeds the baseline, so the
	// subtraction in the message is safe by construction.
	const ceiling = aliasProbePadding / 8
	if after > baseline+ceiling {
		t.Fatalf("REGRESSION: %d bytes still reachable after dropping the caller's buffer, "+
			"against a %d-byte probe — the memo stored the caller's string rather than a clone, "+
			"pinning its backing array behind a %d-byte key, and the bounded-footprint ceiling "+
			"does not hold", after-baseline, aliasProbePadding, len(e.host))
	}
	t.Logf("heap after dropping a %d-byte buffer sliced behind a %d-byte key: %d bytes against a "+
		"%d-byte baseline (ceiling %d)", aliasProbePadding, len(e.host), after, baseline, ceiling)
}

// aliasProbePadding is the buffer the probe host is sliced out of. It stands in
// for net/http's header buffer and is sized so that retaining it is unmistakable
// against GC and allocator noise.
const aliasProbePadding = 16 << 20

// aliasProbeHost returns suffix as a genuine SUBSTRING of a large buffer,
// exactly as r.Host is a slice of the header buffer. The buffer is built and
// dropped inside this function so the caller's frame holds no reference to it
// other than the returned substring — which is what makes dropping that
// substring sufficient to make the buffer unreachable.
func aliasProbeHost(suffix string) string {
	backing := strings.Repeat("a", aliasProbePadding) + suffix
	return backing[aliasProbePadding:]
}

// heapAllocBytes reports currently reachable heap bytes. Callers must GC first.
func heapAllocBytes() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}
