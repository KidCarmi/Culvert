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
	tf.enabled.Store(true)
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
	tf.enabled.Store(true)
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
	tf.enabled.Store(true)
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

// TestApplySync_MergeHoldsWriteLock_BlocksReaders PROVES the review finding
// (PR #587, external review headline comment): the carryForward merge runs
// inside tf.mu.Lock, so while a sync merges a large previous DB, request-path
// readers (CheckURL/CheckDomain take RLock) are locked out for the duration —
// the pre-fix lock hold was an O(1) pointer swap. The cost is accepted
// (bounded, once per sync cycle) and this test documents it: if the recorded
// follow-up lands (merge outside the lock with a pointer recheck), the
// lock-out disappears and this test should be inverted/removed deliberately.
func TestApplySync_MergeHoldsWriteLock_BlocksReaders(t *testing.T) {
	const n = 100_000
	tf := New()
	tf.enabled.Store(true)
	urls := make(map[string]entry, n)
	domains := make(map[string]entry, n)
	for i := 0; i < n; i++ {
		urls[fmt.Sprintf("http://h%[1]d.example/p%[1]d", i)] = entry{Source: sourceURLhaus}
		domains[fmt.Sprintf("h%d.example", i)] = entry{Source: sourceURLhaus}
	}
	tf.urls, tf.domains = urls, domains

	done := make(chan struct{})
	go func() {
		// Both feeds failed → carryForward walks both 100k-entry maps and
		// re-inserts every entry, all under tf.mu.Lock.
		tf.applySync(make(map[string]entry), make(map[string]entry),
			[]string{"URLhaus: down", "OpenPhish: down"},
			map[string]bool{}, time.Now())
		close(done)
	}()

	// Poll the read lock the way a request-path CheckDomain would contend for
	// it. The merge holds the write lock for milliseconds while each poll
	// iteration is sub-microsecond, so observing zero lock-outs is only
	// possible if the merge ran outside the lock.
	var blocked, polls int
	for {
		select {
		case <-done:
			if blocked == 0 {
				t.Fatalf("request-path readers were never locked out across %d polls — merge no longer under the write lock? update/remove this pin deliberately", polls)
			}
			t.Logf("readers locked out on %d of %d lock polls during the merge", blocked, polls)
			return
		default:
		}
		polls++
		if tf.mu.TryRLock() {
			tf.mu.RUnlock()
		} else {
			blocked++
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

// TestSeedForTest_MutatesPublishedMapsInPlace PROVES why the carryForward
// merge must stay under the write lock (or a future lock-scope fix must
// pointer-recheck): the published maps are NOT immutable-after-publish.
// SeedForTest inserts into tf.urls/tf.domains IN PLACE under the lock, so
// iterating those maps outside the lock (the naive "merge outside, swap
// inside" optimization) would be a map read racing a map write.
func TestSeedForTest_MutatesPublishedMapsInPlace(t *testing.T) {
	tf := New()
	urlsRef, domainsRef := tf.urls, tf.domains // aliases of the published maps

	tf.SeedForTest(
		map[string]string{"http://seeded.example/a": sourceURLhaus},
		map[string]string{"seeded.example": sourceURLhaus},
	)

	if _, ok := urlsRef["http://seeded.example/a"]; !ok {
		t.Fatal("SeedForTest replaced tf.urls instead of mutating in place — the merge-outside-the-lock optimization may now be safe; revisit the applySync lock-scope follow-up")
	}
	if _, ok := domainsRef["seeded.example"]; !ok {
		t.Fatal("SeedForTest replaced tf.domains instead of mutating in place — revisit the applySync lock-scope follow-up")
	}
}
