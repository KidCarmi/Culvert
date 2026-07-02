package main

// urlcategories_startup.go — loader for the URL-categories slice. Owns the
// side effects: the catStore load (fatal — categories are policy-load-bearing),
// UT1 name seeding for GUI visibility, the category-groups load, the SaaS feed
// configure, and the optional BadgerDB community feed + syncer goroutine. The
// resolver + DTO live in urlcategories_startup_config.go; the
// initURLCategories shim in main.go wires them.

import (
	"context"
	"strings"
)

// loadURLCategories initialises the URL-categorisation stack and returns the
// UT1 feed syncer (nil when the community feed is disabled) so the shim can
// stash it on startupState.
func loadURLCategories(cfg urlCategoriesStartupConfig, ctx context.Context) *FeedSyncer {
	if err := catStore.Load(cfg.CatPath); err != nil {
		logger.Fatalf("Cannot load URL categories: %v", err)
	}
	logger.Printf("URLCat: %d categories loaded from %s", len(catStore.All()), cfg.CatPath)

	seedUT1CategoryNames()

	if err := globalCategoryGroups.Load(cfg.CategoryGroupsPath); err != nil {
		logger.Printf("CategoryGroups: load error: %v", err)
	}

	// SaaS category feed (dynamic updates from GitHub). Additive merge: new
	// domains added, admin removals preserved. Disabled by default; enabled
	// via the admin GUI.
	globalSaaSFeed.Configure(cfg.SaaSFeedURL, cfg.SaaSFeedInterval)

	// Community URL category feed (BadgerDB, Layer 2). Layer 1 (catStore)
	// remains the priority; BadgerDB is the fallback.
	if cfg.FeedDBPath == "" {
		logger.Printf("CatFeedDB: disabled (set --cat-feed-db for community feed)")
		return nil
	}
	var dbErr error
	communityDB, dbErr = openCommunityDB(cfg.FeedDBPath)
	if dbErr != nil {
		logger.Fatalf("CatFeedDB → cannot open BadgerDB at %s: %v", cfg.FeedDBPath, dbErr)
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
	for _, mappedCat := range ut1CategoryMap {
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
