package threatfeed

// applySync carry-forward tests: only entries owned by a feed that fetched
// cleanly this sync are replaced; everything else is preserved.
// Pre-fix, one sync with both feeds unreachable wiped the entire threat DB
// in memory and (via the saveToDisk right after) on disk — silently
// disabling threat-feed blocking until the next successful sync, durably
// across restarts. Entries imported from the control plane
// ("cluster-sync", ImportFeedData) are never owned by a local fetch and
// must survive local syncs too (Codex review on PR #587).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func seedFeed() *Feed {
	tf := New()
	tf.SetEnabledForTest(true) // publishes the read view; a bare field poke would leave it stale
	tf.urls = map[string]entry{
		"http://evil.example/mal.exe":  {Source: "urlhaus"},
		"http://phish.example/login":   {Source: "openphish"},
		"http://phish.example/verify2": {Source: "openphish"},
	}
	tf.domains = map[string]entry{
		"evil.example":  {Source: "urlhaus"},
		"phish.example": {Source: "openphish"},
	}
	tf.totalEntries.Store(3)
	tf.republishForTest() // the field pokes above bypass the mutators that publish
	return tf
}

func TestApplySync_AllFeedsFailed_KeepsLastKnownGood(t *testing.T) {
	tf := seedFeed()

	// Both fetches failed: nothing was replaced this sync.
	tf.applySync(
		make(map[string]entry), make(map[string]entry),
		[]string{"URLhaus: dial timeout", "OpenPhish: dial timeout"},
		map[string]bool{},
		time.Now(),
	)

	if got, _, _ := tf.Stats(); got != 3 {
		t.Fatalf("totalEntries = %d, want 3 (last-known-good preserved)", got)
	}
	if mal, src := tf.CheckURL("http://evil.example/mal.exe"); !mal || src != "urlhaus" {
		t.Errorf("CheckURL after failed sync = (%v, %q), want (true, urlhaus)", mal, src)
	}
	if mal, _ := tf.CheckDomain("phish.example"); !mal {
		t.Error("CheckDomain after failed sync = false, want true (entry wiped)")
	}
	if ok, _, errSummary := tf.SyncStatus(); ok || errSummary == "" {
		t.Errorf("SyncStatus after failed sync = (ok=%v, err=%q), want failure recorded", ok, errSummary)
	}
}

func TestApplySync_OneFeedFailed_CarriesForwardOnlyThatFeed(t *testing.T) {
	tf := seedFeed()

	// OpenPhish fetched cleanly (with a fresh, smaller set); URLhaus failed.
	fresh := map[string]entry{
		"http://phish.example/new": {Source: "openphish"},
	}
	freshDomains := map[string]entry{
		"newphish.example": {Source: "openphish"},
	}
	tf.applySync(fresh, freshDomains,
		[]string{"URLhaus: HTTP 503"},
		map[string]bool{"openphish": true},
		time.Now(),
	)

	// URLhaus entries carried forward.
	if mal, _ := tf.CheckURL("http://evil.example/mal.exe"); !mal {
		t.Error("failed feed's URL entry was wiped; want carry-forward")
	}
	if mal, _ := tf.CheckDomain("evil.example"); !mal {
		t.Error("failed feed's domain entry was wiped; want carry-forward")
	}
	// Succeeded feed fully replaced: stale entries age out.
	if mal, _ := tf.CheckURL("http://phish.example/login"); mal {
		t.Error("succeeded feed's stale URL entry survived; want full replace")
	}
	if mal, _ := tf.CheckURL("http://phish.example/new"); !mal {
		t.Error("succeeded feed's fresh URL entry missing")
	}
	if mal, _ := tf.CheckDomain("newphish.example"); !mal {
		t.Error("succeeded feed's fresh domain entry missing")
	}
}

func TestApplySync_CleanSync_FullyReplacesFeedOwnedEntries(t *testing.T) {
	tf := seedFeed()
	before := time.Now().Add(-time.Second)

	tf.applySync(
		map[string]entry{"http://fresh.example/x": {Source: "urlhaus"}},
		map[string]entry{"fresh.example": {Source: "urlhaus"}},
		nil, map[string]bool{"urlhaus": true, "openphish": true},
		time.Now(),
	)

	if got, _, _ := tf.Stats(); got != 1 {
		t.Fatalf("totalEntries = %d, want 1 (clean sync fully replaces)", got)
	}
	if mal, _ := tf.CheckURL("http://evil.example/mal.exe"); mal {
		t.Error("stale entry survived a clean sync; want full replace")
	}
	if ok, lastSuccess, errSummary := tf.SyncStatus(); !ok || errSummary != "" || !lastSuccess.After(before) {
		t.Errorf("SyncStatus after clean sync = (ok=%v, lastSuccess=%v, err=%q), want success", ok, lastSuccess, errSummary)
	}
}

func TestApplySync_ClusterSyncEntriesSurviveLocalSync(t *testing.T) {
	tf := New()
	tf.SetEnabledForTest(true) // publishes the read view; a bare field poke would leave it stale
	// DP state: entries imported from the CP snapshot, not from a local fetch.
	tf.ImportFeedData(
		map[string]int64{"http://cp-known.example/mal": time.Now().Unix()},
		map[string]int64{"cp-known.example": time.Now().Unix()},
	)

	// Local sync where both public feeds FAILED: cluster entries must survive
	// (pre-fix this wiped and persisted an empty DB on the data plane).
	tf.applySync(
		make(map[string]entry), make(map[string]entry),
		[]string{"URLhaus: dial timeout", "OpenPhish: dial timeout"},
		map[string]bool{},
		time.Now(),
	)
	if mal, src := tf.CheckDomain("cp-known.example"); !mal || src != "cluster-sync" {
		t.Fatalf("cluster-sync domain after failed local sync = (%v, %q), want (true, cluster-sync)", mal, src)
	}

	// Local sync where both feeds SUCCEEDED: cluster entries are still not
	// owned by a local fetch and must survive until the next snapshot
	// re-import (ImportFeedData replaces them wholesale).
	tf.applySync(
		map[string]entry{"http://fresh.example/x": {Source: "urlhaus"}},
		map[string]entry{"fresh.example": {Source: "urlhaus"}},
		nil, map[string]bool{"urlhaus": true, "openphish": true},
		time.Now(),
	)
	if mal, _ := tf.CheckURL("http://cp-known.example/mal"); !mal {
		t.Error("cluster-sync URL wiped by a clean local sync; want preserved")
	}
	if mal, _ := tf.CheckDomain("cp-known.example"); !mal {
		t.Error("cluster-sync domain wiped by a clean local sync; want preserved")
	}
	if mal, _ := tf.CheckDomain("fresh.example"); !mal {
		t.Error("locally-fetched domain missing after clean sync")
	}
}

func TestFetchFeedInto_ZeroEntrySuccessDoesNotReplace(t *testing.T) {
	// An HTTP 200 with an empty (or comment-only) body returns (0, nil) from
	// fetchTextFeed. That must NOT count as a clean fetch: marking the source
	// replaced would wipe its previous entries exactly like the hard-error
	// case the carry-forward fix closed.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "# maintenance — no entries")
	}))
	defer empty.Close()

	tf := New()
	tf.SetEnabledForTest(true) // publishes the read view; a bare field poke would leave it stale
	urls, domains := map[string]entry{}, map[string]entry{}
	replaced, failure := tf.fetchFeedInto(empty.URL, sourceURLhaus, "URLhaus", urls, domains)
	if replaced {
		t.Fatal("zero-entry fetch reported replaced=true; previous entries would be wiped")
	}
	if failure == "" {
		t.Error("zero-entry fetch reported no failure; staleness would be invisible in SyncStatus")
	}

	full := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "http://evil.example/mal.exe")
	}))
	defer full.Close()
	replaced, failure = tf.fetchFeedInto(full.URL, sourceURLhaus, "URLhaus", urls, domains)
	if !replaced || failure != "" {
		t.Fatalf("non-empty fetch = (replaced=%v, failure=%q), want (true, \"\")", replaced, failure)
	}
	if _, ok := urls["http://evil.example/mal.exe"]; !ok {
		t.Error("fetched entry missing from urls map")
	}
}

// TestApplySync_MergeHoldsWriteLock_ButRequestPathIsNotBlocked is the amended
// form of the PR #587 review pin.
//
// The original recorded finding was that the carryForward merge runs inside
// tf.mu.Lock, so while a sync merges a large previous DB the REQUEST PATH
// (CheckURL/CheckDomain, which then took tf.mu.RLock) was locked out for the
// duration. The lock-free readView made the second half of that claim false:
// the request path no longer touches tf.mu at all, so a multi-millisecond merge
// is invisible to it. Only the cold readers (saveToDisk, DomainAllowlist, the
// admin surfaces) still contend, which is the accepted, bounded cost.
//
// Both halves are asserted here so neither can regress silently:
//
//  1. the merge still holds the write lock (the original observation — cold
//     readers are still locked out, so the pin keeps its teeth); and
//  2. CheckDomain keeps answering THROUGHOUT that window, from the previous
//     generation of tables, with no lock acquisition at all.
//
// (2) is the regression guard for the readView: if the per-request lookups ever
// go back to taking tf.mu, a 100k-entry merge stalls every in-flight request
// and this fails.
func TestApplySync_MergeHoldsWriteLock_ButRequestPathIsNotBlocked(t *testing.T) {
	const n = 100_000
	tf := New()
	tf.SetEnabledForTest(true) // publishes the read view; a bare field poke would leave it stale
	urls := make(map[string]entry, n)
	domains := make(map[string]entry, n)
	for i := 0; i < n; i++ {
		urls[fmt.Sprintf("http://h%[1]d.example/p%[1]d", i)] = entry{Source: sourceURLhaus}
		domains[fmt.Sprintf("h%d.example", i)] = entry{Source: sourceURLhaus}
	}
	tf.urls, tf.domains = urls, domains
	tf.republishForTest()

	done := make(chan struct{})
	go func() {
		// Both feeds failed → carryForward walks both 100k-entry maps and
		// re-inserts every entry, all under tf.mu.Lock.
		tf.applySync(make(map[string]entry), make(map[string]entry),
			[]string{"URLhaus: down", "OpenPhish: down"},
			map[string]bool{}, time.Now())
		close(done)
	}()

	// Poll the write-lock window the way a COLD reader would, and on every
	// iteration also run a request-path lookup. The merge holds the write lock
	// for milliseconds while each poll iteration is sub-microsecond, so
	// observing zero cold lock-outs would mean the merge left the lock.
	var blocked, polls, lookups int
	for {
		select {
		case <-done:
			if blocked == 0 {
				t.Fatalf("cold readers were never locked out across %d polls — merge no longer under the write lock? update this pin deliberately", polls)
			}
			t.Logf("cold readers locked out on %d of %d lock polls; %d request-path lookups completed unblocked during the merge", blocked, polls, lookups)
			return
		default:
		}
		polls++
		if tf.mu.TryRLock() {
			tf.mu.RUnlock()
		} else {
			blocked++
			// The write lock is HELD right now. A request-path lookup must
			// still complete — off the published view, without the lock.
			if mal, _ := tf.CheckDomain("h1.example"); !mal {
				t.Fatal("CheckDomain missed a known domain mid-merge — the published view was not self-consistent")
			}
			lookups++
		}
	}
}

// TestFetchFeedInto_TruncatedNonZeroBodyReplaces_DocumentedResidual PROVES
// the accepted residual named in the review: the zero-entry guard has no
// magnitude floor. An HTTP 200 whose body was honestly truncated at a clean
// line boundary to a HANDFUL of entries (not zero) counts as a clean fetch
// and fully replaces the feed — the previous, much larger set is dropped.
// This pins current behavior; if a diff-magnitude guard is added (the
// CHAOS-08-style "N→~0" floor), update this test deliberately.
func TestFetchFeedInto_TruncatedNonZeroBodyReplaces_DocumentedResidual(t *testing.T) {
	tiny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "http://only-survivor.example/x") // 1 entry where 3 existed
	}))
	defer tiny.Close()

	tf := seedFeed() // 1 urlhaus URL + 2 openphish URLs seeded

	newURLs, newDomains := map[string]entry{}, map[string]entry{}
	replaced, failure := tf.fetchFeedInto(tiny.URL, sourceURLhaus, "URLhaus", newURLs, newDomains)
	if !replaced || failure != "" {
		t.Fatalf("truncated-but-nonzero fetch = (replaced=%v, failure=%q); the documented residual expects (true, \"\") — a magnitude floor was added, update this pin", replaced, failure)
	}

	tf.applySync(newURLs, newDomains, nil,
		map[string]bool{sourceURLhaus: true}, time.Now())

	if mal, _ := tf.CheckURL("http://evil.example/mal.exe"); mal {
		t.Fatal("old urlhaus entry survived a truncated replace — magnitude guard now active, update this pin")
	}
	if mal, _ := tf.CheckURL("http://only-survivor.example/x"); !mal {
		t.Error("truncated fetch's own entry missing")
	}
}

// TestSeedForTest_ReplacesRatherThanMutatesPublishedMaps is the INVERSE of the
// tripwire this test used to be.
//
// It previously proved that SeedForTest inserted into tf.urls/tf.domains IN
// PLACE, and warned that the "merge outside the lock, swap inside" optimization
// was therefore unsafe. The lock-free readView (threatfeed.go) inverted that
// requirement: the per-request lookups now read the published maps with NO lock
// at all, so an in-place insert into a published map is a data race against
// every in-flight request — not merely against a hypothetical future
// optimization. SeedForTest was converted to copy-then-swap accordingly.
//
// The assertion is kept, pointed the other way, because it is the cheapest
// guard on the contract the whole read path rests on: a map reachable from a
// published readView is never written in place.
func TestSeedForTest_ReplacesRatherThanMutatesPublishedMaps(t *testing.T) {
	tf := New()
	tf.SetEnabledForTest(true)                 // New() yields an idle feed; Init is what enables it
	urlsRef, domainsRef := tf.urls, tf.domains // aliases of the published maps

	tf.SeedForTest(
		map[string]string{"http://seeded.example/a": sourceURLhaus},
		map[string]string{"seeded.example": sourceURLhaus},
	)

	if _, ok := urlsRef["http://seeded.example/a"]; ok {
		t.Fatal("SeedForTest wrote into the previously-published tf.urls — a published map must never be mutated in place; the lock-free CheckURL/CheckDomain read it without a lock")
	}
	if _, ok := domainsRef["seeded.example"]; ok {
		t.Fatal("SeedForTest wrote into the previously-published tf.domains — see above")
	}
	// The swap itself must still be observable through the read path.
	if mal, _ := tf.CheckURL("http://seeded.example/a"); !mal {
		t.Error("seeded URL not visible through CheckURL after the swap")
	}
	if mal, _ := tf.CheckDomain("seeded.example"); !mal {
		t.Error("seeded domain not visible through CheckDomain after the swap")
	}
}
