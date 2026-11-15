package catdb

// catdb_lookup_txn_test.go — the correctness wall for the Layer-2 domain
// walk's single read transaction.
//
// These run in the DEFAULT suite, because the hazard the change introduces is
// a correctness hazard, not a throughput one: the walk now reads every label of
// one categorisation on a single transaction, and probes them by re-slicing one
// backing array instead of converting a fresh string per label.
//
//   - TestCommunityLookup_MatchesPerLabelTxnWalk is the differential oracle: the
//     one-transaction walk must answer EXACTLY what the frozen per-label walk
//     answers, for every host shape, including the error classifications.
//   - TestCommunityLookup_DepthPrecedenceSurvivesKeyReuse pins depth
//     precedence, which is what makes a disturbed shared key array show up as a
//     wrong answer rather than a plausible one.
//   - TestCommunityLookup_WalkIsNotTornByAConcurrentFeedWrite pins the
//     consistency property the single transaction introduces.
//   - TestCommunityLookup_OpensOneTransactionPerWalk is the structural guard, in
//     the same idiom as the CHAOS-74 guard wall: allocation counts drift with
//     badger versions, so the "one db.View per walk" property is asserted
//     against the source directly as well as through the allocation gate in
//     catdb_lookup_txn_benchgate_test.go (`-tags benchgate`).

import (
	"go/ast"
	"testing"
)

// lookupOracleHosts covers every shape the walk can take: a hit at each depth,
// misses of each depth, the bare-TLD stop, and the inputs that normalisation
// has to fold before the walk ever runs.
var lookupOracleHosts = []string{
	"facebook.com",               // hit, one read
	"www.facebook.com",           // hit at the parent
	"a.b.c.www.facebook.com",     // hit after four strips
	"FACEBOOK.COM",               // case folding
	"facebook.com.",              // trailing dot
	"facebook.com:8443",          // port
	"malware.io",                 // hit, two-label
	"unknown.example.com",        // miss, shallow
	"a.b.c.cdn.example.com",      // miss, deep
	"site0001.example",           // hit in the padding
	"deep.site0001.example",      // hit at the parent, padding
	"com",                        // bare TLD: no read at all past the first
	"localhost",                  // single label
	"example.co.uk",              // miss, public-suffix shape
	"",                           // empty: badger's ErrEmptyKey path
	"xn--80ak6aa92e.com",         // A-label
	"пример.com",                 // U-label, folded by normalisation
	"192.0.2.1",                  // literal IPv4
	"[2001:db8::1]",              // literal IPv6
	"trailing..dots.example.com", // empty label
}

// TestCommunityLookup_MatchesPerLabelTxnWalk is the differential oracle.
//
// It compares the FAULT DELTA as well as the answer, and that is not a
// refinement — without it the oracle is blind to the thing CHAOS-74 exists to
// prevent. Lookup answers ("", false) from ALL THREE of its error arms and from
// a clean miss, so the answer alone cannot distinguish "not in the feed" from
// "the store failed to answer". A regression that collapsed a store error back
// into a clean miss — precisely the pre-CHAOS-74 `if err != nil { return "",
// false }` that getExact's doc says must never come back — would leave both
// shapes at ("", false) and this test green. LookupFaults is the only
// observable that separates them, so the oracle reads it.
func TestCommunityLookup_MatchesPerLabelTxnWalk(t *testing.T) {
	db := benchCommunityStore(t)
	faults := func() uint64 {
		n, _, _ := db.LookupFaults()
		return n
	}
	sawAFault := false
	for _, host := range lookupOracleHosts {
		before := faults()
		gotCat, gotOK := db.Lookup(host)
		gotFaults := faults() - before

		before = faults()
		wantCat, wantOK := lookupPerLabelTxn(db, host)
		wantFaults := faults() - before

		if gotCat != wantCat || gotOK != wantOK {
			t.Errorf("Lookup(%q) = (%q, %v); the frozen per-label walk answers (%q, %v) — the single-transaction walk changed an answer",
				host, gotCat, gotOK, wantCat, wantOK)
		}
		if gotFaults != wantFaults {
			t.Errorf("Lookup(%q) counted %d store fault(s); the frozen per-label walk counted %d — the single-transaction walk reclassified an error",
				host, gotFaults, wantFaults)
		}
		if gotFaults > 0 {
			sawAFault = true
		}
	}
	// Negative control for the control: if no input in the matrix reaches the
	// fault arm at all, the comparison above is vacuous and proves nothing.
	// The empty host does (badger answers ErrEmptyKey, which is not
	// ErrKeyNotFound and therefore not a clean miss).
	if !sawAFault {
		t.Error("no host in the oracle matrix reached Lookup's store-fault arm, so the fault-delta comparison is vacuous; keep an input that badger refuses (the empty host)")
	}
}

// TestCommunityLookup_DepthPrecedenceSurvivesKeyReuse pins depth precedence: a
// hit must carry the value stored for the label it was found at, never for a
// longer or shorter one.
//
// An independent review correctly observed that this is NOT, strictly, an
// aliasing test — the shipped walk only ever narrows the slice and never writes
// a byte, and badger never mutates the key it is handed, so there is no aliased
// state for the test to distinguish, and it passes unchanged against the
// pre-change string walk. The name says what it pins, not what motivated it.
//
// It is kept, and kept here, because depth precedence is exactly what MAKES a
// corruption of the shared array observable: a distinct category at every depth
// of one chain turns a disturbed key into a wrong ANSWER rather than a
// plausible one. Verified by mutation — writing a byte of the array that the
// later suffixes contain (`key[len(key)-1] = 'x'`) fails this test, the
// differential oracle, and the pre-existing DomainWalking test.
func TestCommunityLookup_DepthPrecedenceSurvivesKeyReuse(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// A distinct category at every depth of one chain, so an answer taken from
	// the wrong label is detectable rather than merely plausible.
	if err := db.BulkWrite(map[string]string{
		"d.c.b.a.example.com": "Depth5",
		"c.b.a.example.com":   "Depth4",
		"b.a.example.com":     "Depth3",
		"a.example.com":       "Depth2",
		"example.com":         "Depth1",
	}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}
	for _, tc := range []struct{ host, want string }{
		{"d.c.b.a.example.com", "Depth5"},
		{"c.b.a.example.com", "Depth4"},
		{"b.a.example.com", "Depth3"},
		{"a.example.com", "Depth2"},
		{"example.com", "Depth1"},
		// Each of these must strip exactly down to the first stored label.
		{"z.d.c.b.a.example.com", "Depth5"},
		{"y.z.c.b.a.example.com", "Depth4"},
		{"x.y.z.a.example.com", "Depth2"},
	} {
		got, ok := db.Lookup(tc.host)
		if !ok || got != tc.want {
			t.Errorf("Lookup(%q) = (%q, %v), want (%q, true)", tc.host, got, ok, tc.want)
		}
	}
}

// TestCommunityLookup_OpensOneTransactionPerWalk asserts the property against
// the source, because it is the property and not the allocation count that the
// change is about: the transaction is what takes badger's process-wide oracle
// mutex and sends on its single watermark channel.
func TestCommunityLookup_OpensOneTransactionPerWalk(t *testing.T) {
	methods := communityDBMethods(t)
	for _, name := range []string{"Lookup", "walk", "getExact"} {
		if methods[name] == nil {
			t.Fatalf("method %s no longer exists; this wall is not looking at the right sources", name)
		}
	}

	if got := countTxnOpeners(methods["Lookup"]); got != 1 {
		t.Errorf("Lookup opens %d badger transactions, want exactly 1 for the whole walk", got)
	}
	for _, name := range []string{"walk", "getExact"} {
		if got := countTxnOpeners(methods[name]); got != 0 {
			t.Errorf("%s opens %d badger transactions; the walk must read on the transaction Lookup hands it, or every label pays the oracle mutex and two watermark-channel sends again",
				name, got)
		}
	}
}

// txnOpeners are every badger entry point that mints a transaction, and
// therefore every entry point that takes the oracle mutex and sends on the
// watermark channel.
//
// Counting only `View` was not enough, and an independent review proved it:
// replacing `c.db.View` inside getExact with `c.db.NewTransaction(false)` plus
// `defer txn.Discard()` — the exact per-label regression this wall is named
// for — passed the wall. The CHAOS-74 guard wall does not catch it either,
// because getExact is a guardedOnlyHelper and its `c.db` reference is therefore
// exempt from the containment check. Validated by mutation after the fix.
var txnOpeners = map[string]bool{
	"View":             true,
	"Update":           true,
	"NewTransaction":   true,
	"NewTransactionAt": true,
	"NewWriteBatch":    true,
	"NewWriteBatchAt":  true,
	"NewStreamWriter":  true,
}

// countTxnOpeners counts calls that mint a badger transaction in fn.
func countTxnOpeners(fn *ast.FuncDecl) int {
	n := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && txnOpeners[sel.Sel.Name] {
			n++
		}
		return true
	})
	return n
}

// TestCommunityLookup_WalkIsNotTornByAConcurrentFeedWrite exercises the one
// property this change INTRODUCES, which nothing else covered: because every
// label of one categorisation is now read at a single read timestamp, a feed
// BulkWrite landing mid-walk can no longer be half-visible to one answer.
//
// The walk probes `b.a.example.com` then `a.example.com`. A writer concurrently
// publishes a category for `a.example.com`. Before this change the two probes
// had independent read timestamps, so the second could observe a write the
// first could not; now they cannot disagree. The assertion is deliberately the
// weak, true one — a lookup may legitimately see the write or not see it, and
// which it sees is a race — so what is pinned is that the answer is always ONE
// of the two consistent states and never a torn third, and that the store never
// reports a fault while being written. Run under -race, where the shuffled
// determinism job will also run it.
func TestCommunityLookup_WalkIsNotTornByAConcurrentFeedWrite(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	const (
		host = "b.a.example.com"
		base = "a.example.com"
		want = "Social Media"
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			if err := db.BulkWrite(map[string]string{base: want}); err != nil {
				t.Errorf("BulkWrite: %v", err)
				return
			}
		}
	}()

	for i := 0; i < 2000; i++ {
		cat, ok := db.Lookup(host)
		switch {
		case !ok && cat == "":
			// The write is not visible to this read timestamp yet. Legitimate.
		case ok && cat == want:
			// The write is visible. Also legitimate.
		default:
			t.Fatalf("Lookup(%q) = (%q, %v) during a concurrent feed write; the only consistent answers are (%q, true) and (\"\", false)",
				host, cat, ok, want)
		}
	}
	<-done

	if faults, memFaults, degraded := db.LookupFaults(); faults != 0 || memFaults != 0 || degraded {
		t.Errorf("LookupFaults() = (%d, %d, %v) after concurrent reads and writes; a feed write must not make the store report faults",
			faults, memFaults, degraded)
	}
	// After the writer has finished, the entry must be visible.
	if cat, ok := db.Lookup(host); !ok || cat != want {
		t.Errorf("Lookup(%q) after the write completed = (%q, %v), want (%q, true)", host, cat, ok, want)
	}
}

// TestCommunityLookup_DeepAuthorityWalksEveryLabel covers repeated re-slicing
// past the 5-label shapes the benchmarks use: a 12-label authority strips ten
// times before the stored label, so an array handled correctly only for short
// hosts fails here.
func TestCommunityLookup_DeepAuthorityWalksEveryLabel(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	if err := db.BulkWrite(map[string]string{"example.com": "News"}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}
	host := "a.b.c.d.e.f.g.h.i.j.example.com"
	if cat, ok := db.Lookup(host); !ok || cat != "News" {
		t.Errorf("Lookup(%q) = (%q, %v), want (\"News\", true)", host, cat, ok)
	}
	// The same depth with nothing stored must be a clean miss, not a fault.
	before, _, _ := db.LookupFaults()
	if cat, ok := db.Lookup("a.b.c.d.e.f.g.h.i.j.absent.test"); ok || cat != "" {
		t.Errorf("deep uncategorised host = (%q, %v), want (\"\", false)", cat, ok)
	}
	if after, _, _ := db.LookupFaults(); after != before {
		t.Errorf("a deep clean miss counted %d store fault(s), want 0", after-before)
	}
}
