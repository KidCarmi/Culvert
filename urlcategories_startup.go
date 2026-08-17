package main

// urlcategories_startup.go — loader for the URL-categories slice. Owns the
// side effects: the catStore load (fatal — categories are policy-load-bearing),
// UT1 name seeding for GUI visibility, the category-groups load, the SaaS feed
// configure, and the optional BadgerDB community feed + syncer goroutine. The
// resolver + DTO live in urlcategories_startup_config.go; the
// initURLCategories shim in main.go wires them.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KidCarmi/Culvert/internal/catdb"
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
	return loadCommunityFeedDB(cfg, ctx)
}

// loadCommunityFeedDB opens the Layer-2 community store and starts its syncer.
//
// CHAOS-50 — this used to be `logFatalf`. A damaged store directory (torn
// MANIFEST after an unclean container kill, a corrupt table, a missing volume)
// stopped the whole gateway from booting, permanently, over a store that holds
// no authoritative state: Layer 2 is a cache of a downloadable feed, Layer 1
// (catStore) is the admin-managed source of truth, and every consumer of
// `communityDB` is already nil-tolerant, so a nil store is byte-identical to
// running without `-cat-feed-db`. `-cat-feed-db /data/catfeeddb` is set by the
// shipped docker-compose.yml, whose `restart: unless-stopped` turned the fatal
// into an unattended crash-loop with no admin UI to recover from.
//
// The posture is now the one CHAOS-05/07 already established for corrupt state
// on the boot path: quarantine the evidence, keep booting, make it visible.
// OpenResilient additionally survives the case badger will not let a caller
// catch — a corrupt `.sst` panics out of a goroutine badger spawns — by
// refusing to hand it a directory a previous process died inside of.
func loadCommunityFeedDB(cfg urlCategoriesStartupConfig, ctx context.Context) *FeedSyncer {
	health := catFeedDBHealth{Configured: true, Path: cfg.FeedDBPath}

	db, rec, dbErr := catdb.OpenResilient(cfg.FeedDBPath)
	health.ResidualCopies = len(rec.ResidualQuarantines)
	if rec.Quarantined {
		health.Quarantines = 1
	}

	// The outcome is reported ONCE, after it is known. A quarantine that
	// succeeded followed by a replacement that would not open (volume went full
	// or read-only in between) is a FAILURE, not a recovery: reporting the
	// quarantine first would queue "re-created empty, the feed re-syncs
	// automatically" and then contradict it with "could not be opened".
	if dbErr != nil {
		// Degrade, never exit. The detail carries the cause for the log and the
		// alert; the viewer-role diagnostics row carries only the impact.
		health.Available = false
		health.Detail = dbErr.Error()
		noteCatFeedDBState(health)
		reportCatFeedDBUnavailable(cfg.FeedDBPath, rec, dbErr)
		return nil
	}

	communityDB = db
	health.Available = true
	health.Recovered = rec.Quarantined
	noteCatFeedDBState(health)
	reportCatFeedDBOpened(cfg.FeedDBPath, rec)

	syncer := newFeedSyncer(communityDB, cfg.FeedURL, cfg.FeedSyncInterval)
	globalUT1FeedSyncer = syncer // UC-6: expose Stats() to /metrics
	syncer.Start(ctx)
	logger.Printf("CatFeedDB: BadgerDB at %s, sync every %s", cfg.FeedDBPath, cfg.FeedSyncInterval)
	return syncer
}

// reportCatFeedDBOpened reports a store that came up, alerting only when this
// boot actually moved a damaged copy aside.
//
// The alert reuses the CHAOS-05/07 `state_file_corrupt` event rather than
// inventing a second name: the operator action is precisely the one that event
// already means — corrupt state was quarantined at startup and there is evidence
// on disk to reconcile.
//
// A recovery that was TRIGGERED but skipped, on a store that then opened fine,
// is log-only. The commonest reason to skip is a live lock holder, i.e. a
// concurrent boot, where alerting would page somebody about a benign race.
// Alert on evidence or on impact, never on a suspicion that resolved itself.
func reportCatFeedDBOpened(path string, rec catdb.Recovery) {
	if !rec.Quarantined {
		if rec.Trigger != catdb.TriggerNone {
			logger.Printf("CatFeedDB: %q", sanitizeLog(fmt.Sprintf(
				"community category store at %s looked damaged (%s: %s) but was NOT quarantined (%s); it opened normally",
				path, rec.Trigger, rec.Cause, rec.Skipped)))
		}
		return
	}
	detail := fmt.Sprintf("community category store at %s was damaged (%s: %s) — quarantined to %s and re-created empty; the feed re-syncs automatically. Delete the quarantined copy once reconciled to reclaim disk",
		path, rec.Trigger, rec.Cause, rec.QuarantinePath)
	logger.Printf("CatFeedDB: %q", sanitizeLog(detail))
	deferStartupAlert("state_file_corrupt", AlertPayload{Source: "storage", Detail: detail})
}

// reportCatFeedDBUnavailable emits the SINGLE alert for a store that did not
// come up, folding in the quarantine (or the reason one was not attempted) so
// the operator gets one coherent account instead of two that disagree.
func reportCatFeedDBUnavailable(path string, rec catdb.Recovery, dbErr error) {
	recoveryNote := ""
	switch {
	case rec.Quarantined:
		recoveryNote = fmt.Sprintf(" A damaged copy was quarantined to %s first, so the failure is with the REPLACEMENT store — check the volume for space, permissions, and mount state.", rec.QuarantinePath)
	case rec.Trigger != catdb.TriggerNone:
		recoveryNote = fmt.Sprintf(" It looked damaged (%s) but could not be quarantined (%s).", rec.Trigger, rec.Skipped)
	}
	detail := fmt.Sprintf("community category store at %s could not be opened (%v) — the node is running with admin-managed categories only; category rules that depend on the community feed will not match.%s",
		path, dbErr, recoveryNote)
	logger.Printf("CatFeedDB: %q", sanitizeLog(detail))
	deferStartupAlert("state_file_corrupt", AlertPayload{Source: "storage", Detail: detail})
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
