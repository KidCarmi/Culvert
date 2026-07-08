package main

// blocklist_feed.go — package-main glue for the remote blocklist syncer,
// moved to internal/blocklistfeed (ADR-0002). The alias shim keeps the admin
// API handler (ui_policy.go), the startup slice, admin-settings persistence,
// and the test suite using the original unqualified names. The engine depends
// on the Blocklist hub only through the blocklistfeed.Merger interface (which
// *Blocklist satisfies) and on internal/ssrf for the outbound fetch guard.

import "github.com/KidCarmi/Culvert/internal/blocklistfeed"

// BlocklistSyncer / BlocklistFeed re-exposed unqualified (engine types are
// blocklistfeed.Syncer / .Feed).
type (
	BlocklistSyncer = blocklistfeed.Syncer
	BlocklistFeed   = blocklistfeed.Feed
)

// newBlocklistSyncer re-exposed for the startup slice, the handler, and the
// test suite. *Blocklist satisfies blocklistfeed.Merger via MergeFromLines.
func newBlocklistSyncer(bl *Blocklist) *BlocklistSyncer {
	return blocklistfeed.New(bl)
}

// blFeedDefaultInterval re-exposed for admin-settings restore, the startup
// slice, and the API handler (the process-wide blFeedSyncer var stays in
// main.go alongside the other startup singletons).
const blFeedDefaultInterval = blocklistfeed.DefaultInterval
