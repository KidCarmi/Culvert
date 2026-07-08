package main

// urlcategories_startup_test.go — per-slice tests for the URL-categories
// startup slice (resolver defaults + verbatim interval semantics). The
// loader's collaborators (catStore, category groups, SaaS feed, BadgerDB
// syncer) are owned and tested by their own suites.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestResolveURLCategories_Defaults(t *testing.T) {
	dir := t.TempDir()
	got := resolveURLCategoriesStartupConfig(&FileConfig{}, dir, "", "", "")
	if got.CatPath != "categories.json" {
		t.Errorf("CatPath = %q, want categories.json", got.CatPath)
	}
	if want := filepath.Join(dir, "category_groups.json"); got.CategoryGroupsPath != want {
		t.Errorf("CategoryGroupsPath = %q, want %q", got.CategoryGroupsPath, want)
	}
	if got.SaaSFeedURL != defaultSaaSFeedURL || got.SaaSFeedInterval != 24*time.Hour {
		t.Errorf("SaaS feed = (%q, %v), want (default URL, 24h)", got.SaaSFeedURL, got.SaaSFeedInterval)
	}
	if got.FeedDBPath != "" {
		t.Errorf("FeedDBPath = %q, want empty (community feed off)", got.FeedDBPath)
	}
	if got.FeedSyncInterval != 24*time.Hour {
		t.Errorf("FeedSyncInterval = %v, want 24h default", got.FeedSyncInterval)
	}
}

func TestResolveURLCategories_ConfigAndFlags(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.URLCategoriesFile = "/etc/culvert/cats.json"
	got := resolveURLCategoriesStartupConfig(fc, "/data", "/data/catdb", "https://feed.example/ut1", "6h")
	if got.CatPath != "/etc/culvert/cats.json" {
		t.Errorf("CatPath = %q, want the configured file", got.CatPath)
	}
	if got.FeedDBPath != "/data/catdb" || got.FeedURL != "https://feed.example/ut1" {
		t.Errorf("feed wiring = (%q, %q)", got.FeedDBPath, got.FeedURL)
	}
	if got.FeedSyncInterval != 6*time.Hour {
		t.Errorf("FeedSyncInterval = %v, want 6h", got.FeedSyncInterval)
	}
}

// Verbatim pre-slice semantics: any PARSEABLE interval overrides the default
// (sign/zero not validated); unparseable falls back to 24h. Pinned so a future
// "fix" is a deliberate behavior change, not refactor drift.
func TestResolveURLCategories_IntervalVerbatimSemantics(t *testing.T) {
	if got := resolveURLCategoriesStartupConfig(&FileConfig{}, "", "", "", "garbage"); got.FeedSyncInterval != 24*time.Hour {
		t.Errorf("unparseable interval = %v, want 24h fallback", got.FeedSyncInterval)
	}
	if got := resolveURLCategoriesStartupConfig(&FileConfig{}, "", "", "", "0s"); got.FeedSyncInterval != 0 {
		t.Errorf("parseable 0s = %v, want 0 (verbatim parse-ok-wins)", got.FeedSyncInterval)
	}
}
