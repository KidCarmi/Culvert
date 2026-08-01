package main

import (
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
	swapFeedStatus(t, time.Unix(1_700_000_000, 0)) // default signed-feed status: not configured

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

// F3b-4: the SaaS block now reflects the SIGNED feed runtime status (the legacy raw
// syncer is retired). "configured" is driven by the signed-feed config; the block
// surfaces the derived state, active version, provenance, and process-lifetime failure
// count — never the retired syncer's hostsAddedLastSync/entries fields.
func TestAPIURLCatFeedStatus_SaaSEnabledReportsConfiguredTrue(t *testing.T) {
	snapshotFeedGlobals(t)
	globalUT1FeedSyncer = nil
	s := swapFeedStatus(t, time.Unix(1_700_000_500, 0))
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true, URL: builtinSaaSFeedURL, Protocol: saasFeedProtocolV1}})
	s.noteActivation(viewFor(sourceDownloaded, 7, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{HostsAdded: 7}, 200)

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
		t.Fatalf("saas.configured = false, want true once the signed feed is configured")
	}
	if state, _ := got.SaaS["state"].(string); state != "fresh" {
		t.Errorf("saas.state = %v, want fresh", got.SaaS["state"])
	}
	if v, _ := got.SaaS["activeFeedVersion"].(float64); v != 7 {
		t.Errorf("saas.activeFeedVersion = %v, want 7", got.SaaS["activeFeedVersion"])
	}
	if _, present := got.SaaS["syncFailures"]; !present {
		t.Errorf("saas response should include syncFailures")
	}
	// The retired legacy fields must be gone.
	if _, present := got.SaaS["hostsAddedLastSync"]; present {
		t.Errorf("saas response must not carry the retired legacy hostsAddedLastSync field")
	}
	if _, present := got.SaaS["entries"]; present {
		t.Errorf("saas response must not carry the retired legacy entries field")
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
