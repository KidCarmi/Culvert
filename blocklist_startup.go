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
//     URL branch constructs the syncer with default interval but
//     never spawns the goroutine.

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
	if cfg.Path != "" {
		if err := bl.Load(cfg.Path); err != nil {
			if os.IsNotExist(err) {
				logger.Printf("Blocklist not found at %s — starting with empty list", cfg.Path)
			} else {
				logger.Fatalf("Cannot load blocklist: %v", err)
			}
		} else {
			logger.Printf("Blocklist loaded: %d entries from %s", bl.Count(), cfg.Path)
		}
	}

	if cfg.FeedURL != "" {
		blFeedSyncer = newBlocklistSyncer(bl, cfg.FeedURL, cfg.FeedInterval)
		blFeedSyncer.Start(ctx)
		logger.Printf("BlocklistFeed: syncing from %s every %s", cfg.FeedURL, cfg.FeedInterval)
	} else {
		blFeedSyncer = newBlocklistSyncer(bl, "", cfg.FeedInterval)
	}
}
