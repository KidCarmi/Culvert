package main

// blocklist_feed_multi_test.go — coverage for the multi-feed rework of
// BlocklistSyncer: feed CRUD via the syncer and the admin API handler,
// persistence round-trip through admin_settings.json, and migration of
// legacy single-feed settings files.
//
// No parallel tests; these snapshot/restore the package-global
// blFeedSyncer and adminSettingsPath via t.Cleanup, following the
// pattern in blocklist_startup_test.go and admin_settings_nilfeed_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

func newTestBlocklistSyncer(t *testing.T) *BlocklistSyncer {
	t.Helper()
	ensureBlocklistStartupTestLogger(t)
	testBL := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	return newBlocklistSyncer(testBL)
}

func swapFeedSyncer(t *testing.T, bs *BlocklistSyncer) {
	t.Helper()
	orig := blFeedSyncer
	blFeedSyncer = bs
	t.Cleanup(func() { blFeedSyncer = orig })
}

func swapAdminSettingsPath(t *testing.T, path string) {
	t.Helper()
	adminSettingsMu.Lock()
	orig := adminSettingsPath
	adminSettingsPath = path
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsMu.Lock()
		adminSettingsPath = orig
		adminSettingsMu.Unlock()
	})
}

// ─── Syncer CRUD ─────────────────────────────────────────────────────

func TestBlocklistSyncer_MultiFeedCRUD(t *testing.T) {
	bs := newTestBlocklistSyncer(t)

	bs.SetFeed("https://feeds.example/a.txt", 12*time.Hour)
	bs.SetFeed("https://feeds.example/b.txt", 0) // manual-only
	feeds := bs.Feeds()
	if len(feeds) != 2 {
		t.Fatalf("Feeds() len = %d; want 2", len(feeds))
	}
	// Sorted by URL: a.txt before b.txt.
	if feeds[0].URL != "https://feeds.example/a.txt" || feeds[1].URL != "https://feeds.example/b.txt" {
		t.Errorf("Feeds() order = %q, %q; want a.txt then b.txt", feeds[0].URL, feeds[1].URL)
	}
	if feeds[0].Interval != 12*time.Hour {
		t.Errorf("a.txt interval = %v; want 12h", feeds[0].Interval)
	}
	if feeds[1].Interval != 0 {
		t.Errorf("b.txt interval = %v; want 0 (disabled)", feeds[1].Interval)
	}

	// Update keeps the same feed count and changes only the interval.
	bs.SetFeed("https://feeds.example/a.txt", 48*time.Hour)
	feeds = bs.Feeds()
	if len(feeds) != 2 {
		t.Fatalf("Feeds() len after update = %d; want 2", len(feeds))
	}
	if feeds[0].Interval != 48*time.Hour {
		t.Errorf("a.txt interval after update = %v; want 48h", feeds[0].Interval)
	}

	if !bs.RemoveFeed("https://feeds.example/b.txt") {
		t.Error("RemoveFeed(b.txt) = false; want true")
	}
	if bs.RemoveFeed("https://feeds.example/b.txt") {
		t.Error("second RemoveFeed(b.txt) = true; want false")
	}
	if got := len(bs.Feeds()); got != 1 {
		t.Errorf("Feeds() len after remove = %d; want 1", got)
	}
}

func TestBlocklistSyncer_ZeroValueSafe(t *testing.T) {
	var bs BlocklistSyncer // zero value, as constructed in security_audit_test.go
	if feeds := bs.Feeds(); len(feeds) != 0 {
		t.Errorf("zero-value Feeds() = %v; want empty", feeds)
	}
	bs.SetFeed("https://feeds.example/z.txt", time.Hour) // must lazily init the map
	if got := len(bs.Feeds()); got != 1 {
		t.Errorf("Feeds() len = %d; want 1", got)
	}
	if bs.RemoveFeed("https://feeds.example/nope") {
		t.Error("RemoveFeed of unknown URL on zero-value syncer = true; want false")
	}
}

// allowLoopbackSSRF seeds the SSRF DNS cache so isPrivateHost treats
// 127.0.0.1 (the httptest server) as public and swaps in a plain dialer for
// the duration of the test, letting the sync-time and dial-time guards pass.
// Cleanup restores pristine fail-closed behaviour. Tests in this package run
// sequentially (no t.Parallel), so the window cannot leak.
func allowLoopbackSSRF(t *testing.T) {
	t.Helper()
	origDial := ssrfSafeDialContext
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	ssrfSafeDialContext = dialer.DialContext
	ssrf.CacheStore("127.0.0.1", false)
	t.Cleanup(func() {
		ssrfSafeDialContext = origDial
		ssrf.CacheDelete("127.0.0.1")
	})
}

func TestBlocklistSyncer_SyncFeed_MergesAndCounts(t *testing.T) {
	bs := newTestBlocklistSyncer(t)
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# comment\nmulti-feed-a.invalid\nmulti-feed-b.invalid\n"))
	}))
	defer srv.Close()

	bs.SetFeed(srv.URL, 0)
	added, err := bs.SyncFeed(srv.URL)
	if err != nil {
		t.Fatalf("SyncFeed: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d; want 2", added)
	}
	feeds := bs.Feeds()
	if len(feeds) != 1 {
		t.Fatalf("Feeds() len = %d; want 1", len(feeds))
	}
	if feeds[0].ImportedCount != 2 {
		t.Errorf("ImportedCount = %d; want 2", feeds[0].ImportedCount)
	}
	if feeds[0].LastSync.IsZero() {
		t.Error("LastSync should be set after a successful sync")
	}
	if feeds[0].LastError != "" {
		t.Errorf("LastError = %q; want empty", feeds[0].LastError)
	}

	// Second sync of the same content adds nothing new but succeeds.
	added, err = bs.SyncFeed(srv.URL)
	if err != nil || added != 0 {
		t.Errorf("re-sync: added = %d, err = %v; want 0, nil", added, err)
	}
}

// TestBlocklistSyncer_SyncFeed_BlocksPrivateHost pins the inline sync-time
// SSRF guard: even a feed that somehow entered the store (e.g. a tampered
// settings file bypassing the admin-API guard) must be refused at fetch
// time when its host resolves to a private address.
func TestBlocklistSyncer_SyncFeed_BlocksPrivateHost(t *testing.T) {
	bs := newTestBlocklistSyncer(t)
	bs.SetFeed("http://127.0.0.1:9/feed.txt", 0)
	_, err := bs.SyncFeed("http://127.0.0.1:9/feed.txt")
	if err == nil || !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("SyncFeed to loopback: err = %v; want SSRF-guard rejection", err)
	}
	feeds := bs.Feeds()
	if len(feeds) != 1 || feeds[0].LastError == "" {
		t.Errorf("feed should record the guard rejection in LastError; got %+v", feeds)
	}
}

func TestBlocklistSyncer_SyncFeed_UsesSSRFSafeDialContext(t *testing.T) {
	bs := newTestBlocklistSyncer(t)
	const feedURL = "http://feeds.example/feed.txt"
	const sentinel = "dial guard sentinel"
	ssrf.CacheStore("feeds.example", false)
	t.Cleanup(func() {
		ssrf.CacheDelete("feeds.example")
	})

	origDial := ssrfSafeDialContext
	called := false
	ssrfSafeDialContext = func(_ context.Context, _ string, addr string) (net.Conn, error) {
		called = true
		if addr != "feeds.example:80" {
			t.Errorf("dial addr = %q; want feeds.example:80", addr)
		}
		return nil, errors.New(sentinel)
	}
	t.Cleanup(func() { ssrfSafeDialContext = origDial })

	bs.SetFeed(feedURL, 0)
	_, err := bs.SyncFeed(feedURL)
	if !called {
		t.Fatal("SyncFeed did not use ssrfSafeDialContext")
	}
	if err == nil || !strings.Contains(err.Error(), sentinel) {
		t.Fatalf("SyncFeed err = %v; want sentinel from ssrfSafeDialContext", err)
	}
}

func TestBlocklistSyncer_SyncFeed_BlocksPrivateRedirect(t *testing.T) {
	bs := newTestBlocklistSyncer(t)
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.2:9/feed.txt", http.StatusFound)
	}))
	defer srv.Close()

	bs.SetFeed(srv.URL, 0)
	_, err := bs.SyncFeed(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect blocked by SSRF guard") {
		t.Fatalf("SyncFeed redirect err = %v; want redirect SSRF guard rejection", err)
	}
}

func TestBlocklistSyncer_SyncFeed_UnknownURL(t *testing.T) {
	bs := newTestBlocklistSyncer(t)
	if _, err := bs.SyncFeed("https://feeds.example/unknown.txt"); err == nil {
		t.Error("SyncFeed of unconfigured URL should error")
	}
}

// ─── Admin API handler ───────────────────────────────────────────────

func TestAPIBlocklistFeed_MultiFeedLifecycle(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	swapAdminSettingsPath(t, "") // disable background settings writes
	// Pre-seed the SSRF DNS cache so the handler's isPrivateHost guard
	// passes without real DNS resolution (fails closed on NXDOMAIN).
	ssrf.CacheStore("feeds.example", false)

	post := func(url, interval string) *httptest.ResponseRecorder {
		r := jsonReq(http.MethodPost, "/api/blocklist/feed",
			map[string]string{"url": url, "interval": interval})
		w := httptest.NewRecorder()
		apiBlocklistFeed(w, r)
		return w
	}

	if w := post("https://feeds.example/one.txt", "12h"); w.Code != http.StatusOK {
		t.Fatalf("POST one.txt: status = %d; want 200 (%s)", w.Code, w.Body.String())
	}
	if w := post("https://feeds.example/two.txt", "off"); w.Code != http.StatusOK {
		t.Fatalf("POST two.txt: status = %d; want 200 (%s)", w.Code, w.Body.String())
	}

	// GET lists both feeds.
	r := getReq("/api/blocklist/feed")
	w := httptest.NewRecorder()
	apiBlocklistFeed(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d; want 200", w.Code)
	}
	var resp struct {
		Feeds []struct {
			URL      string `json:"url"`
			Interval string `json:"interval"`
		} `json:"feeds"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if len(resp.Feeds) != 2 {
		t.Fatalf("GET feeds len = %d; want 2", len(resp.Feeds))
	}
	if resp.Feeds[0].URL != "https://feeds.example/one.txt" || resp.Feeds[0].Interval != "12h0m0s" {
		t.Errorf("feed[0] = %+v; want one.txt @ 12h0m0s", resp.Feeds[0])
	}
	if resp.Feeds[1].Interval != "0s" {
		t.Errorf("feed[1] interval = %q; want 0s (off)", resp.Feeds[1].Interval)
	}

	// DELETE removes one; deleting again is a 404.
	del := func() *httptest.ResponseRecorder {
		r := adminCtx(httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
			"/api/blocklist/feed?url=https%3A%2F%2Ffeeds.example%2Ftwo.txt", http.NoBody))
		w := httptest.NewRecorder()
		apiBlocklistFeed(w, r)
		return w
	}
	if w := del(); w.Code != http.StatusOK {
		t.Fatalf("DELETE: status = %d; want 200 (%s)", w.Code, w.Body.String())
	}
	if w := del(); w.Code != http.StatusNotFound {
		t.Errorf("second DELETE: status = %d; want 404", w.Code)
	}
	if got := len(blFeedSyncer.Feeds()); got != 1 {
		t.Errorf("feeds after delete = %d; want 1", got)
	}
}

func TestAPIBlocklistFeed_PostRequiresURL(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	swapAdminSettingsPath(t, "")

	r := jsonReq(http.MethodPost, "/api/blocklist/feed",
		map[string]string{"url": "", "interval": "24h"})
	w := httptest.NewRecorder()
	apiBlocklistFeed(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty URL: status = %d; want 400", w.Code)
	}
}

func TestAPIBlocklistFeed_DeleteRequiresURL(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	swapAdminSettingsPath(t, "")

	r := adminCtx(httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/blocklist/feed", http.NoBody))
	w := httptest.NewRecorder()
	apiBlocklistFeed(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing url param: status = %d; want 400", w.Code)
	}
}

// ─── Persistence round-trip + legacy migration ───────────────────────

func TestAdminSettings_BlocklistFeedsRoundTrip(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	blFeedSyncer.SetFeed("https://feeds.example/rt-a.txt", 12*time.Hour)
	blFeedSyncer.SetFeed("https://feeds.example/rt-b.txt", 0)
	SaveAdminSettings()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings file not written: %v", err)
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if len(s.BlocklistFeeds) != 2 {
		t.Fatalf("persisted feeds = %d; want 2 (%s)", len(s.BlocklistFeeds), data)
	}
	if !s.BlocklistFeedsSaved {
		t.Error("blocklist_feeds_saved = false; want true (sentinel must be set on save)")
	}
	if s.BlocklistFeedURL != "" {
		t.Errorf("legacy blocklist_feed_url = %q; want empty (no longer written)", s.BlocklistFeedURL)
	}

	// Restore into a fresh syncer — both feeds and intervals must survive.
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	applyBlocklistFeeds(&s)
	feeds := blFeedSyncer.Feeds()
	if len(feeds) != 2 {
		t.Fatalf("restored feeds = %d; want 2", len(feeds))
	}
	if feeds[0].URL != "https://feeds.example/rt-a.txt" || feeds[0].Interval != 12*time.Hour {
		t.Errorf("restored feed[0] = %+v; want rt-a.txt @ 12h", feeds[0])
	}
	if feeds[1].Interval != 0 {
		t.Errorf("restored feed[1] interval = %v; want 0 (disabled survives restart)", feeds[1].Interval)
	}
}

func TestAdminSettings_LegacySingleFeedMigration(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))

	// A settings file written before the multi-feed rework.
	s := AdminSettings{
		BlocklistFeedURL:      "https://feeds.example/legacy.txt",
		BlocklistFeedInterval: "48h",
	}
	applyBlocklistFeeds(&s)
	feeds := blFeedSyncer.Feeds()
	if len(feeds) != 1 {
		t.Fatalf("migrated feeds = %d; want 1", len(feeds))
	}
	if feeds[0].URL != "https://feeds.example/legacy.txt" {
		t.Errorf("migrated URL = %q; want legacy.txt", feeds[0].URL)
	}
	if feeds[0].Interval != 48*time.Hour {
		t.Errorf("migrated interval = %v; want 48h", feeds[0].Interval)
	}
}

// TestAdminSettings_FeedsReplaceStartupSeed guards the restore contract:
// the persisted feed list is authoritative over the YAML/CLI-seeded feed,
// so a config-seeded feed that was deleted or replaced in the GUI does not
// resurrect on restart.
func TestAdminSettings_FeedsReplaceStartupSeed(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	blFeedSyncer.SetFeed("https://feeds.example/from-yaml.txt", blFeedDefaultInterval)

	s := AdminSettings{
		BlocklistFeedsSaved: true,
		BlocklistFeeds:      []BlocklistFeedSetting{{URL: "https://feeds.example/from-gui.txt", Interval: "12h"}},
	}
	applyBlocklistFeeds(&s)
	feeds := blFeedSyncer.Feeds()
	if len(feeds) != 1 || feeds[0].URL != "https://feeds.example/from-gui.txt" {
		t.Errorf("restored feeds = %+v; want exactly the persisted from-gui.txt (yaml seed replaced)", feeds)
	}
}

// TestAdminSettings_DeleteAllFeedsSurvivesRestart: a settings file saved
// after the admin removed every feed (sentinel set, empty list) must clear
// the YAML/CLI-seeded feed too.
func TestAdminSettings_DeleteAllFeedsSurvivesRestart(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	blFeedSyncer.SetFeed("https://feeds.example/from-yaml.txt", blFeedDefaultInterval)

	s := AdminSettings{BlocklistFeedsSaved: true}
	applyBlocklistFeeds(&s)
	if feeds := blFeedSyncer.Feeds(); len(feeds) != 0 {
		t.Errorf("feeds = %+v; want empty (GUI delete-all is durable)", feeds)
	}
}

// TestAdminSettings_NoFeedOpinionKeepsStartupSeed: a pre-feature settings
// file (sentinel unset, no legacy URL) must leave the startup seed alone.
func TestAdminSettings_NoFeedOpinionKeepsStartupSeed(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))
	blFeedSyncer.SetFeed("https://feeds.example/from-yaml.txt", blFeedDefaultInterval)

	applyBlocklistFeeds(&AdminSettings{})
	feeds := blFeedSyncer.Feeds()
	if len(feeds) != 1 || feeds[0].URL != "https://feeds.example/from-yaml.txt" {
		t.Errorf("feeds = %+v; want the yaml seed untouched", feeds)
	}
}

func TestAdminSettings_LegacyMigration_BadIntervalDefaults(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t))

	s := AdminSettings{BlocklistFeedURL: "https://feeds.example/legacy2.txt"}
	applyBlocklistFeeds(&s)
	feeds := blFeedSyncer.Feeds()
	if len(feeds) != 1 {
		t.Fatalf("migrated feeds = %d; want 1", len(feeds))
	}
	if feeds[0].Interval != blFeedDefaultInterval {
		t.Errorf("interval = %v; want default %v when legacy interval missing", feeds[0].Interval, blFeedDefaultInterval)
	}
}
