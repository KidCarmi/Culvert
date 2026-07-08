package main

// feedsync.go — package-main glue for the UT1 URL-category feed syncer, moved
// to internal/feedsync (ADR-0002). The alias shim keeps the urlcategories
// startup slice, the metrics surface, and main.go's singleton using the
// original unqualified names. The UT1 sync-failure counter is package-owned
// now (feedsync.SyncFailures, read by urlcat_metrics.go).

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// FeedSyncer is re-exposed unqualified (engine type is feedsync.Syncer).
type FeedSyncer = feedsync.Syncer

// newFeedSyncer re-exposed for the urlcategories startup slice and the test
// suite (the package constructor is feedsync.New).
func newFeedSyncer(db *CommunityDB, feedURL string, syncInterval time.Duration) *FeedSyncer {
	return feedsync.New(db, feedURL, syncInterval)
}
