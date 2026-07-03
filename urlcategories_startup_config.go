package main

// urlcategories_startup_config.go — resolved config for the URL-categories
// slice (Layer-1 catStore, category groups, SaaS feed, Layer-2 BadgerDB
// community feed). Pure DTO + a single side-effect-free resolver invoked from
// the initURLCategories shim. CLI flag values and the data dir are passed IN
// so the resolver stays pure (slice convention pinned by
// startup_slice_contract_test.go).

import (
	"path/filepath"
	"time"
)

// urlCategoriesStartupConfig carries the resolved URL-categorisation inputs.
// The loader consumes this struct and owns the store loads, UT1 seeding, and
// the feed-syncer construction/start.
type urlCategoriesStartupConfig struct {
	// CatPath is the Layer-1 categories file (default "categories.json").
	CatPath string

	// CategoryGroupsPath is the category-groups store under the data dir.
	CategoryGroupsPath string

	// SaaSFeedURL / SaaSFeedInterval configure the curated SaaS category
	// auto-sync (disabled by default; enabled via admin GUI).
	SaaSFeedURL      string
	SaaSFeedInterval time.Duration

	// FeedDBPath is the BadgerDB location for the Layer-2 community feed.
	// "" disables the community feed entirely.
	FeedDBPath string

	// FeedURL is the UT1 feed source; FeedSyncInterval its cadence.
	// Interval semantics are VERBATIM from the pre-slice init: any value
	// that parses overrides the 24h default (sign/zero not validated here —
	// behavior-preserving move).
	FeedURL          string
	FeedSyncInterval time.Duration
}

// resolveURLCategoriesStartupConfig is the single startup-time reader of the
// URL-categorisation config surface. Pure and deterministic; safe on a
// zero-value *FileConfig.
func resolveURLCategoriesStartupConfig(fc *FileConfig, dataDirVal, catFeedDB, catFeedURL, catSyncIntvl string) urlCategoriesStartupConfig {
	catPath := fc.Proxy.URLCategoriesFile
	if catPath == "" {
		catPath = "categories.json"
	}
	syncD := 24 * time.Hour
	if catSyncIntvl != "" {
		if d, err := time.ParseDuration(catSyncIntvl); err == nil {
			syncD = d
		}
	}
	return urlCategoriesStartupConfig{
		CatPath:            catPath,
		CategoryGroupsPath: filepath.Join(dataDirVal, "category_groups.json"),
		SaaSFeedURL:        defaultSaaSFeedURL,
		SaaSFeedInterval:   24 * time.Hour,
		FeedDBPath:         catFeedDB,
		FeedURL:            catFeedURL,
		FeedSyncInterval:   syncD,
	}
}
