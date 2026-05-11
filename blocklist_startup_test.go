package main

// blocklist_startup_test.go — P4.1 / S1 coverage for the extracted
// blocklist startup slice.
//
// Resolver tests are pure (no globals touched). Loader tests
// snapshot/restore the package-level `bl` store and `blFeedSyncer`
// pointer via t.Cleanup so they are safe under -shuffle=on /
// -count=2. The feed-syncer goroutine in the loader-with-URL test is
// parented to a per-test cancellable context (never the package-
// global appLifecycleCtx).

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var blocklistStartupLoggerMu sync.Mutex

func ensureBlocklistStartupTestLogger(t *testing.T) {
	t.Helper()
	blocklistStartupLoggerMu.Lock()
	defer blocklistStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// snapshotBlocklistGlobals saves and resets the package-level bl
// store and the blFeedSyncer pointer, restoring them on t.Cleanup so
// the loader tests don't leak state into the rest of the suite.
func snapshotBlocklistGlobals(t *testing.T) {
	t.Helper()
	oldBL := bl
	oldSyncer := blFeedSyncer
	bl = &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	blFeedSyncer = nil
	t.Cleanup(func() {
		bl = oldBL
		blFeedSyncer = oldSyncer
	})
}

// ─── Resolver ────────────────────────────────────────────────────────

func TestResolveBlocklistStartupConfig_PathFromResolvedPath(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.Blocklist = "/should/be/ignored.list"
	got := resolveBlocklistStartupConfig(fc, "/already-resolved.list")
	if got.Path != "/already-resolved.list" {
		t.Errorf("Path = %q; want %q (resolvedPath wins; fc.Proxy.Blocklist is ignored)", got.Path, "/already-resolved.list")
	}
}

func TestResolveBlocklistStartupConfig_EmptyResolvedPathStaysEmpty(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.Blocklist = "/from-config.list"
	got := resolveBlocklistStartupConfig(fc, "")
	if got.Path != "" {
		t.Errorf("Path = %q; want empty (resolver must not re-read fc.Proxy.Blocklist)", got.Path)
	}
}

func TestResolveBlocklistStartupConfig_EmptyFileConfig(t *testing.T) {
	got := resolveBlocklistStartupConfig(&FileConfig{}, "")
	if got.Path != "" {
		t.Errorf("Path = %q; want empty", got.Path)
	}
	if got.FeedURL != "" {
		t.Errorf("FeedURL = %q; want empty", got.FeedURL)
	}
	if got.FeedInterval != blFeedDefaultInterval {
		t.Errorf("FeedInterval = %v; want default %v", got.FeedInterval, blFeedDefaultInterval)
	}
}

func TestResolveBlocklistStartupConfig_FeedURLFromFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.BlocklistFeedURL = "https://example.invalid/list.txt"
	got := resolveBlocklistStartupConfig(fc, "")
	if got.FeedURL != "https://example.invalid/list.txt" {
		t.Errorf("FeedURL = %q; want propagated", got.FeedURL)
	}
}

func TestResolveBlocklistStartupConfig_FeedIntervalParse(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", blFeedDefaultInterval},
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"garbage", blFeedDefaultInterval},
		{"0s", blFeedDefaultInterval},
		{"-5m", blFeedDefaultInterval},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			fc := &FileConfig{}
			fc.Proxy.BlocklistFeedInterval = tc.raw
			got := resolveBlocklistStartupConfig(fc, "")
			if got.FeedInterval != tc.want {
				t.Errorf("FeedInterval for %q = %v; want %v", tc.raw, got.FeedInterval, tc.want)
			}
		})
	}
}

// ─── Loader ──────────────────────────────────────────────────────────

func TestLoadBlocklist_EmptyConfigStillAssignsSyncer(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	snapshotBlocklistGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	loadBlocklist(blocklistStartupConfig{FeedInterval: blFeedDefaultInterval}, ctx)

	if blFeedSyncer == nil {
		t.Fatal("loadBlocklist with empty cfg must still assign blFeedSyncer (UI handlers depend on it)")
	}
	url, _, _, interval := blFeedSyncer.Stats()
	if url != "" {
		t.Errorf("Stats URL = %q; want empty", url)
	}
	if interval != blFeedDefaultInterval {
		t.Errorf("Stats interval = %v; want default %v", interval, blFeedDefaultInterval)
	}
}

// TestLoadBlocklist_EmptyURLPinsDefaultInterval guards the
// behaviour-preservation invariant that the empty-URL branch always
// constructs blFeedSyncer with blFeedDefaultInterval, regardless of
// cfg.FeedInterval. The pre-extraction body hard-coded
// blFeedDefaultInterval in this branch; if a future refactor passes
// cfg.FeedInterval through instead, the admin API's first read of
// blFeedSyncer.Stats() would expose a user-set
// blocklist_feed_interval value even though auto-sync was disabled
// at startup.
func TestLoadBlocklist_EmptyURLPinsDefaultInterval(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	snapshotBlocklistGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// cfg.FeedInterval is non-default but cfg.FeedURL is empty — the
	// loader MUST pin the syncer to blFeedDefaultInterval.
	loadBlocklist(blocklistStartupConfig{
		FeedURL:      "",
		FeedInterval: 30 * time.Minute,
	}, ctx)

	if blFeedSyncer == nil {
		t.Fatal("blFeedSyncer must be non-nil")
	}
	_, _, _, interval := blFeedSyncer.Stats()
	if interval != blFeedDefaultInterval {
		t.Errorf("empty-URL branch must pin to default; got interval = %v, want %v",
			interval, blFeedDefaultInterval)
	}
}

func TestLoadBlocklist_LoadsFromTempFile(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	snapshotBlocklistGlobals(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	// One domain per line — bl.Load splits on "\n".
	if err := os.WriteFile(path, []byte("p4-1-loader-test.invalid\n"), 0o600); err != nil {
		t.Fatalf("write blocklist file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	loadBlocklist(blocklistStartupConfig{Path: path, FeedInterval: blFeedDefaultInterval}, ctx)

	if bl.Count() == 0 {
		t.Errorf("bl.Count() = 0 after loading non-empty file at %s; want > 0", path)
	}
	if blFeedSyncer == nil {
		t.Fatal("blFeedSyncer must be non-nil even when only a path was provided")
	}
}

func TestLoadBlocklist_MissingPathIsNonFatal(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	snapshotBlocklistGlobals(t)

	missing := filepath.Join(t.TempDir(), "does-not-exist.list")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// os.IsNotExist branch — logger.Printf "starting with empty list",
	// no panic, no exit. Asserting on the post-condition (syncer still
	// assigned, bl empty) is sufficient; we don't shell out to capture
	// the log line.
	loadBlocklist(blocklistStartupConfig{Path: missing, FeedInterval: blFeedDefaultInterval}, ctx)

	if blFeedSyncer == nil {
		t.Fatal("blFeedSyncer must be non-nil after a non-existent-path load")
	}
	if bl.Count() != 0 {
		t.Errorf("bl.Count() = %d; want 0 after missing-file load", bl.Count())
	}
}

func TestLoadBlocklist_FeedURLStartsSyncer(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	snapshotBlocklistGlobals(t)

	// Per-test cancellable ctx so the syncer goroutine exits at test
	// end. The URL is RFC 2606 / RFC 6761 reserved — the immediate
	// sync HTTP call will fail and log, but that is fine and matches
	// production behaviour when a feed URL is briefly unreachable.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	const wantURL = "http://blocklist-feed.invalid/list.txt"
	loadBlocklist(blocklistStartupConfig{
		FeedURL:      wantURL,
		FeedInterval: 30 * time.Minute,
	}, ctx)

	if blFeedSyncer == nil {
		t.Fatal("blFeedSyncer must be non-nil after a FeedURL load")
	}
	url, _, _, interval := blFeedSyncer.Stats()
	if url != wantURL {
		t.Errorf("Stats URL = %q; want %q", url, wantURL)
	}
	if interval != 30*time.Minute {
		t.Errorf("Stats interval = %v; want 30m", interval)
	}
}
