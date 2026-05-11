package main

// blocklist_startup.go — startup-time loader for the blocklist slice
// (P4.1 / S1). Mirrors the pre-extraction body of initBlocklist
// (main.go:737–768) byte-for-byte except parameterized: cfg supplies
// the resolved path / feed URL / interval, and ctx parents the
// auto-sync goroutine.
//
// Behaviour invariants preserved:
//   - bl.Load(cfg.Path) only when cfg.Path != ""
//   - logger.Fatalf on a non-IsNotExist load error (documented hard-
//     fatal site; ARCH_DISCOVERY Risk #5, line 181)
//   - Log strings unchanged so operators see the same startup banner.
//   - blFeedSyncer is ALWAYS assigned (both branches) — UI handlers
//     at admin_settings.go:161 and ui_policy.go:245 rely on it being
//     non-nil after init.
//   - .Start(ctx) is only invoked when cfg.FeedURL != "". The empty-
//     URL branch constructs the syncer with blFeedDefaultInterval
//     (NOT cfg.FeedInterval) to match the pre-extraction behaviour:
//     a user-set blocklist_feed_interval is dormant until a feed URL
//     is configured, at which point the admin API's SetFeed() takes
//     over interval management.

import (
	"context"
	"os"
)

// loadBlocklist applies cfg to the package-global bl store and the
// blFeedSyncer pointer. ctx parents the auto-sync goroutine when
// cfg.FeedURL is non-empty; production passes appLifecycleCtx so the
// existing early-phase `app-lifecycle-cancel` shutdown hook stops it
// at SIGTERM. Tests pass a per-test cancellable ctx.
func loadBlocklist(cfg blocklistStartupConfig, ctx context.Context) {
	tryLoadBlocklistFile(cfg.Path)

	if cfg.FeedURL != "" {
		blFeedSyncer = newBlocklistSyncer(bl, cfg.FeedURL, cfg.FeedInterval)
		blFeedSyncer.Start(ctx)
		logger.Printf("BlocklistFeed: syncing from %s every %s", cfg.FeedURL, cfg.FeedInterval)
	} else {
		// Empty-URL branch intentionally pins to blFeedDefaultInterval
		// rather than cfg.FeedInterval — see file-level invariants.
		blFeedSyncer = newBlocklistSyncer(bl, "", blFeedDefaultInterval)
	}
}

// tryLoadBlocklistFile applies the pre-extraction file-load semantics
// for path. Extracted from loadBlocklist to keep the nesting depth
// inside loadBlocklist below the linter threshold; behaviour and log
// strings are byte-equivalent to the inline form.
func tryLoadBlocklistFile(path string) {
	if path == "" {
		return
	}
	err := bl.Load(path)
	switch {
	case err == nil:
		logger.Printf("Blocklist loaded: %d entries from %s", bl.Count(), path)
	case os.IsNotExist(err):
		logger.Printf("Blocklist not found at %s — starting with empty list", path)
	default:
		logger.Fatalf("Cannot load blocklist: %v", err)
	}
}
