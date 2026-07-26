package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
)

// apiURLCatFeedStatus exposes the same UT1/SaaS feed freshness+failure state
// the /metrics writer already reads (urlcat_metrics.go) so an admin can see
// a stalled or failing category feed from the GUI instead of scraping
// Prometheus or reading logs.

func TestAPIURLCatFeedStatus_NotConfigured(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = nil
	globalSaaSFeed = saasfeed.New(saasfeed.Deps{}) // Configure never called → not enabled

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/urlcat/feed-status", http.NoBody)
	apiURLCatFeedStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got struct {
		UT1  map[string]any `json:"ut1"`
		SaaS map[string]any `json:"saas"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if configured, _ := got.UT1["configured"].(bool); configured {
		t.Errorf("ut1.configured = true, want false when globalUT1FeedSyncer is nil")
	}
	if configured, _ := got.SaaS["configured"].(bool); configured {
		t.Errorf("saas.configured = true, want false when the SaaS feed URL is unset")
	}
	if _, present := got.UT1["entries"]; present {
		t.Errorf("ut1 response should omit entries/lastSync/syncFailures when not configured")
	}
}

func TestAPIURLCatFeedStatus_UT1ConfiguredReportsStatsAndFailures(t *testing.T) {
	snapshotFeedGlobals(t)

	ut1Time := time.Unix(1_700_000_000, 0)
	ut1 := newFeedSyncer(nil, "https://example.invalid/blacklists.tar.gz", time.Hour)
	ut1.SeedStats(ut1Time, 42)
	globalUT1FeedSyncer = ut1
	globalSaaSFeed = saasfeed.New(saasfeed.Deps{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/urlcat/feed-status", http.NoBody)
	apiURLCatFeedStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got struct {
		UT1 map[string]any `json:"ut1"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if configured, _ := got.UT1["configured"].(bool); !configured {
		t.Fatalf("ut1.configured = false, want true")
	}
	if entries, _ := got.UT1["entries"].(float64); entries != 42 {
		t.Errorf("ut1.entries = %v, want 42", got.UT1["entries"])
	}
	if lastSync, _ := got.UT1["lastSync"].(string); lastSync != ut1Time.UTC().Format(time.RFC3339) {
		t.Errorf("ut1.lastSync = %v, want %v", lastSync, ut1Time.UTC().Format(time.RFC3339))
	}
	if _, present := got.UT1["syncFailures"]; !present {
		t.Errorf("ut1 response should include syncFailures when configured")
	}
}

// SaaS "configured" is driven by the syncer's own Enabled() state (set by
// Configure/Stop), so this exercises the real transition rather than the
// SeedStats-only test seam used above for UT1.
func TestAPIURLCatFeedStatus_SaaSEnabledReportsConfiguredTrue(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = nil

	saas := saasfeed.New(saasfeed.Deps{Lifecycle: context.Background})
	saas.Configure("http://localhost:9999/feed.json", time.Hour) // unreachable local port, fails fast — mirrors internal/saasfeed's own Configure test
	t.Cleanup(saas.Stop)
	// SeedStats after Configure to pin a deterministic "hosts added" value,
	// overwriting whatever the async unreachable-URL sync attempt wrote.
	saas.SeedStats(time.Unix(1_700_000_500, 0), 7)
	globalSaaSFeed = saas

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/urlcat/feed-status", http.NoBody)
	apiURLCatFeedStatus(w, r)

	var got struct {
		SaaS map[string]any `json:"saas"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if configured, _ := got.SaaS["configured"].(bool); !configured {
		t.Fatalf("saas.configured = false, want true once Configure has run")
	}
	if _, present := got.SaaS["syncFailures"]; !present {
		t.Errorf("saas response should include syncFailures when configured")
	}
	// Regression: the SaaS syncer's Stats() count is hosts newly ADDED on the
	// last sync (mergeSaaSCategories' return value), not the feed's total
	// size — 0 is normal on a routine unchanged sync. It must be surfaced
	// under its own field name, never as "entries" (which would misread as
	// an empty/broken feed on a healthy sync that added nothing new).
	if added, _ := got.SaaS["hostsAddedLastSync"].(float64); added != 7 {
		t.Errorf("saas.hostsAddedLastSync = %v, want 7", got.SaaS["hostsAddedLastSync"])
	}
	if _, present := got.SaaS["entries"]; present {
		t.Errorf(`saas response must not use the "entries" key — it would misrepresent the added-this-sync delta as the feed's total size`)
	}
}

func TestAPIURLCatFeedStatus_MethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/urlcat/feed-status", http.NoBody)
	apiURLCatFeedStatus(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
