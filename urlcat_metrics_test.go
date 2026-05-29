package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// 1. All six new metric names are rendered.
func TestURLCatMetrics_AllNamesRendered(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = newFeedSyncer(nil, "x", time.Hour)
	globalSaaSFeed = &SaaSFeedSyncer{}

	body := scrapeMetrics(t)
	for _, name := range []string{
		"culvert_category_feed_last_sync_timestamp_seconds",
		"culvert_category_feed_entries",
		"culvert_saas_feed_last_sync_timestamp_seconds",
		"culvert_saas_feed_entries",
		"culvert_category_feed_sync_failures_total",
		"culvert_saas_feed_sync_failures_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics missing %q", name)
		}
	}
}

// 2. Timestamp renders 0 when never synced.
func TestURLCatMetrics_NeverSyncedRendersZero(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = newFeedSyncer(nil, "x", time.Hour) // lastSync = zero time
	globalSaaSFeed = &SaaSFeedSyncer{}                       // lastSync = zero time

	body := scrapeMetrics(t)
	for _, want := range []string{
		"culvert_category_feed_last_sync_timestamp_seconds 0",
		"culvert_saas_feed_last_sync_timestamp_seconds 0",
		"culvert_category_feed_entries 0",
		"culvert_saas_feed_entries 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// 3. Populated Stats() render the expected timestamp/count values.
func TestURLCatMetrics_PopulatedRendersValues(t *testing.T) {
	snapshotFeedGlobals(t)
	ut1Time := time.Unix(1_700_000_000, 0)
	saasTime := time.Unix(1_700_000_500, 0)

	ut1 := newFeedSyncer(nil, "x", time.Hour)
	ut1.lastSync.Store(ut1Time)
	ut1.totalDomains.Store(42)
	globalUT1FeedSyncer = ut1
	globalSaaSFeed = &SaaSFeedSyncer{lastSync: saasTime, lastCount: 7}

	body := scrapeMetrics(t)
	for _, want := range []string{
		fmt.Sprintf("culvert_category_feed_last_sync_timestamp_seconds %d", ut1Time.Unix()),
		"culvert_category_feed_entries 42",
		fmt.Sprintf("culvert_saas_feed_last_sync_timestamp_seconds %d", saasTime.Unix()),
		"culvert_saas_feed_entries 7",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// 4a. UT1 failure counter increments on a deterministic, network-free sync
// failure: an invalid URL (control char) fails at request build, before any dial.
func TestURLCatMetrics_UT1FailureCounterIncrements(t *testing.T) {
	before := statCategoryFeedSyncFailures.Load()
	fs := newFeedSyncer(nil, "\x7f", time.Hour) // DEL control char → url.Parse rejects
	fs.Sync()
	if got := statCategoryFeedSyncFailures.Load(); got != before+1 {
		t.Errorf("statCategoryFeedSyncFailures = %d, want %d", got, before+1)
	}
}

// 4b. SaaS failure counter increments on a deterministic, network-free sync
// failure: a URL that fails the validSaaSFeedURL guard returns before any fetch.
func TestURLCatMetrics_SaaSFailureCounterIncrements(t *testing.T) {
	before := statSaaSFeedSyncFailures.Load()
	s := &SaaSFeedSyncer{feedURL: "not-a-valid-url"} // fails validSaaSFeedURL regex
	s.Sync(context.Background())
	if got := statSaaSFeedSyncFailures.Load(); got != before+1 {
		t.Errorf("statSaaSFeedSyncFailures = %d, want %d", got, before+1)
	}
}
