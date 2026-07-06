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
	tf.enabled = true
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
	tf.enabled = true
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
	tf.enabled = true
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
