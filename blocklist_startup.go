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
//   - blFeedSyncer is ALWAYS assigned — UI handlers and
//     SaveAdminSettings rely on it being non-nil after init.
//   - .Start(ctx) is ALWAYS invoked: the scheduler must run even with
//     zero feeds at startup, because feeds added via the admin API
//     (or restored later by LoadAdminSettings) are picked up on the
//     next scheduler tick. Before the multi-feed rework the loop only
//     started when cfg.FeedURL was set, so GUI-configured feeds never
//     auto-synced.

import (
	"context"
	"os"
)

// loadBlocklist applies cfg to the package-global bl store and the
// blFeedSyncer pointer. ctx parents the scheduler goroutine;
// production passes appLifecycleCtx so the existing early-phase
// `app-lifecycle-cancel` shutdown hook stops it at SIGTERM. Tests
// pass a per-test cancellable ctx.
func loadBlocklist(cfg blocklistStartupConfig, ctx context.Context) {
	tryLoadBlocklistFile(cfg.Path)

	blFeedSyncer = newBlocklistSyncer(bl)
	if cfg.FeedURL != "" {
		blFeedSyncer.SetFeed(cfg.FeedURL, cfg.FeedInterval)
		logger.Printf("BlocklistFeed: syncing from %s every %s", cfg.FeedURL, cfg.FeedInterval)
	}
	blFeedSyncer.Start(ctx)
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
