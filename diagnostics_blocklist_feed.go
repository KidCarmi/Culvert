package main

// diagnostics_blocklist_feed.go — operator-contract row for remote blocklist
// feeds whose most recent sync failed.
//
// A feed's LastError was visible only on the Blocklist feed panel (and the
// /api/blocklist/feed JSON); the one-page diagnostics report, where an operator
// checks "is this node healthy", stayed green while a feed kept failing and the
// blocklist silently aged.
//
// Report-only: derived from the same Feeds() snapshot that endpoint returns.
// Contributes nothing when no feed is configured or every feed's latest attempt
// succeeded. Carries a count only — never a feed URL (which may embed a token)
// or the raw error text. Sync, retry and enforcement behavior are unchanged.

import "fmt"

// checkBlocklistFeeds returns a WARN row when any configured blocklist feed's
// latest attempt failed.
func checkBlocklistFeeds() []OperatorContractCheck {
	feeds := blFeedSyncer.Feeds() // nil-receiver safe
	failing := 0
	for i := range feeds {
		if feeds[i].LastError != "" {
			failing++
		}
	}
	if failing == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "blocklist_feed",
		Status: diagWarn,
		Message: fmt.Sprintf("%d of %d blocklist feed(s) failed their latest sync — "+
			"the blocklist is not being refreshed from them and keeps its last imported entries", failing, len(feeds)),
		OperatorAction: "Open Policy → Blocklist → Feeds, check the Last Error column for each feed, correct the URL or network path, then use Sync Now to confirm recovery.",
	}}
}
