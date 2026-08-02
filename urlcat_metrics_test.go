package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsync"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
)

// snapshotFeedGlobals saves and restores the package globals the UC-6 metrics
// reader touches, so these tests are safe under -count>1 / -shuffle.
func snapshotFeedGlobals(t *testing.T) {
	t.Helper()
	oldTok := metricsToken
	oldUT1 := globalUT1FeedSyncer
	oldSaaS := globalSaaSFeed
	t.Cleanup(func() {
		metricsToken = oldTok
		globalUT1FeedSyncer = oldUT1
		globalSaaSFeed = oldSaaS
	})
	metricsToken = ""
}

func scrapeMetrics(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}
	return w.Body.String()
}

// 1. The UT1 category-feed metric names are rendered. The legacy raw-SaaS-syncer
// metrics (culvert_saas_feed_*) were RETIRED in F3b-4 (the syncer is no longer armed);
// the signed feed's observability is the culvert_saasfeed_* family.
func TestURLCatMetrics_AllNamesRendered(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = newFeedSyncer(nil, "x", time.Hour)

	body := scrapeMetrics(t)
	for _, name := range []string{
		"culvert_category_feed_last_sync_timestamp_seconds",
		"culvert_category_feed_entries",
		"culvert_category_feed_sync_failures_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics missing %q", name)
		}
	}
	// The retired legacy SaaS syncer metrics must be gone.
	for _, gone := range []string{
		"culvert_saas_feed_last_sync_timestamp_seconds",
		"culvert_saas_feed_entries",
		"culvert_saas_feed_sync_failures_total",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("/metrics still emits retired legacy metric %q", gone)
		}
	}
	// The signed-feed metrics ARE present.
	if !strings.Contains(body, "culvert_saasfeed_refresh_total") {
		t.Error("/metrics missing signed-feed culvert_saasfeed_refresh_total")
	}
}

// 2. UT1 timestamp renders 0 when never synced.
func TestURLCatMetrics_NeverSyncedRendersZero(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = newFeedSyncer(nil, "x", time.Hour) // lastSync = zero time

	body := scrapeMetrics(t)
	for _, want := range []string{
		"culvert_category_feed_last_sync_timestamp_seconds 0",
		"culvert_category_feed_entries 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// 3. Populated UT1 Stats() render the expected timestamp/count values.
func TestURLCatMetrics_PopulatedRendersValues(t *testing.T) {
	snapshotFeedGlobals(t)
	ut1Time := time.Unix(1_700_000_000, 0)

	ut1 := newFeedSyncer(nil, "x", time.Hour)
	ut1.SeedStats(ut1Time, 42)
	globalUT1FeedSyncer = ut1

	body := scrapeMetrics(t)
	for _, want := range []string{
		fmt.Sprintf("culvert_category_feed_last_sync_timestamp_seconds %d", ut1Time.Unix()),
		"culvert_category_feed_entries 42",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// 4a. UT1 failure counter increments on a deterministic, network-free sync
// failure: an invalid URL (control char) fails at request build, before any dial.
func TestURLCatMetrics_UT1FailureCounterIncrements(t *testing.T) {
	before := feedsync.SyncFailures()
	fs := newFeedSyncer(nil, "\x7f", time.Hour) // DEL control char → url.Parse rejects
	fs.Sync()
	if got := feedsync.SyncFailures(); got != before+1 {
		t.Errorf("feedsync.SyncFailures = %d, want %d", got, before+1)
	}
}

// 4b. SaaS failure counter increments on a deterministic, network-free sync
// failure: a URL that fails the saasfeed URL guard returns before any fetch.
func TestURLCatMetrics_SaaSFailureCounterIncrements(t *testing.T) {
	before := saasfeed.SyncFailures()
	s := saasfeed.New(saasfeed.Deps{})
	s.SetFeedURLForTest("not-a-valid-url") // fails the package's URL guard
	s.Sync(context.Background())
	if got := saasfeed.SyncFailures(); got != before+1 {
		t.Errorf("saasfeed.SyncFailures = %d, want %d", got, before+1)
	}
}
