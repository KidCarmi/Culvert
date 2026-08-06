package main

// urlcategories_startup.go — loader for the URL-categories slice. Owns the
// side effects: the catStore load (fatal — categories are policy-load-bearing),
// UT1 name seeding for GUI visibility, the category-groups load, the SaaS feed
// configure, and the optional BadgerDB community feed + syncer goroutine. The
// resolver + DTO live in urlcategories_startup_config.go; the
// initURLCategories shim in main.go wires them.

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// loadURLCategories initialises the URL-categorisation stack and returns the
// UT1 feed syncer (nil when the community feed is disabled) so the shim can
// stash it on startupState.
func loadURLCategories(cfg urlCategoriesStartupConfig, ctx context.Context) *FeedSyncer {
	if err := catStore.Load(cfg.CatPath); err != nil {
		logFatalf("Cannot load URL categories: %v", err)
	}
	logger.Printf("URLCat: %d categories loaded from %s", len(catStore.All()), cfg.CatPath)

	seedUT1CategoryNames()

	if err := globalCategoryGroups.Load(cfg.CategoryGroupsPath); err != nil {
		logger.Printf("CategoryGroups: load error: %v", err)
	}

	// Named decryption profiles (referenced per rule; loaded alongside category
	// groups). Non-fatal — an unreadable/corrupt store leaves the set empty and
	// rules fall back to their inline StripALPN/default (byte-identical to today).
	// First run (no file yet) seeds the non-auto-bound recommended-h2 on-ramp.
	_, statErr := os.Stat(cfg.DecryptionProfilesPath)
	dpFirstRun := os.IsNotExist(statErr)
	if err := globalDecryptionProfiles.Load(cfg.DecryptionProfilesPath); err != nil {
		logger.Printf("DecryptionProfiles: load error: %v", err)
	}
	if dpFirstRun && cfg.DecryptionProfilesPath != "" {
		seedDefaultDecryptionProfiles()
	}

	// Admin category overrides (F3a-2). CP-authoritative fleet policy, folded onto
	// the feed snapshot only by the future downloader (F3b) — inert config here.
	// Non-fatal: a missing file is the first-run state (empty overrides); a corrupt
	// or schema-newer file leaves the store empty and is re-synced from the CP.
	if cfg.CategoryOverridesPath != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.CategoryOverridesPath), 0o700); err != nil {
			logger.Printf("CategoryOverrides: cannot create store dir: %v", err)
		} else if err := globalCategoryOverrides.Load(cfg.CategoryOverridesPath); err != nil {
			logger.Printf("CategoryOverrides: load error: %v", err)
		}
	}

	// Signed SaaS URL-category feed (F3b-4). This RETIRES the legacy raw syncer from
	// runtime authority: we no longer arm globalSaaSFeed (no fetch of the old raw GitHub
	// URL, no dual scheduler/writer). The signed-feed lifecycle runs offline-first record
	// recovery + arms the single refresh scheduler; the compiled embedded baseline in
	// catStore preserves safe SaaS category behavior until the signed feed is explicitly
	// enabled (disabled by default; no unsolicited requests). cfg.SaaSFeedURL/Interval are
	// retained on the config struct for the migration/historical-URL contract only.
	startSignedFeedLifecycle(filepath.Dir(cfg.CategoryOverridesPath), ctx)

	// Community URL category feed (BadgerDB, Layer 2). Layer 1 (catStore)
	// remains the priority; BadgerDB is the fallback.
	if cfg.FeedDBPath == "" {
		logger.Printf("CatFeedDB: disabled (set --cat-feed-db for community feed)")
		return nil
	}
	var dbErr error
	communityDB, dbErr = openCommunityDB(cfg.FeedDBPath)
	if dbErr != nil {
		logFatalf("CatFeedDB → cannot open BadgerDB at %s: %v", cfg.FeedDBPath, dbErr)
	}
	syncer := newFeedSyncer(communityDB, cfg.FeedURL, cfg.FeedSyncInterval)
	globalUT1FeedSyncer = syncer // UC-6: expose Stats() to /metrics
	syncer.Start(ctx)
	logger.Printf("CatFeedDB: BadgerDB at %s, sync every %s", cfg.FeedDBPath, cfg.FeedSyncInterval)
	return syncer
}

// seedUT1CategoryNames seeds empty catStore entries for all UT1 mapped
// category names so they appear in the Category Groups dropdown. The names
// must exist in catStore (Layer 1) for the GUI to list them, even though the
// domains live in BadgerDB (Layer 2); lookupHostCategory checks both layers.
func seedUT1CategoryNames() {
	ut1Seeded := 0
	seen := map[string]bool{}
	for _, mappedCat := range feedsync.MappedCategories() {
		lc := strings.ToLower(mappedCat)
		if seen[lc] {
			continue
		}
		seen[lc] = true
		if catStore.GetByName(mappedCat) == nil {
			_ = catStore.Set(mappedCat, []string{}, true) // empty, built-in
			ut1Seeded++
		}
	}
	if ut1Seeded > 0 {
		catStore.Save()
		logger.Printf("URLCat: seeded %d UT1 category name(s) into catStore for GUI visibility", ut1Seeded)
	}
}
