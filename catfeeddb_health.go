package main

// catfeeddb_health.go — CHAOS-50: observability for the Layer-2 community
// category store's boot outcome.
//
// The store is the ONE thing on the boot path that used to take the whole
// appliance down when the data volume was damaged (`logFatalf` in
// urlcategories_startup.go, and — worse — an uncatchable panic out of
// badger.Open on a corrupt table). It now degrades or self-heals instead, and
// this file is the other half of that change: a degradation nobody can see is
// the failure mode the register's §1 theme is about.
//
// Surfaces, all of which already exist so no new operator vocabulary is
// introduced:
//
//   - `/api/diagnostics` — the `category_feed_db` operator-contract row.
//   - `/metrics` — culvert_catfeeddb_available / _quarantines_total /
//     _quarantined_copies.
//   - alerts — the existing `state_file_corrupt` event (CHAOS-05/07), which
//     already means "corrupt state quarantined at startup"; a second event name
//     for the same operator action would be drift.
//   - logs.
//
// Deliberately NOT wired into /readyz. A node running Layer-1-only
// categorisation is fully able to serve traffic — it is exactly the posture of
// a node started without `-cat-feed-db` — so failing readiness would take a
// healthy gateway out of a load-balancer rotation over a degraded cache.

import (
	"fmt"
	"sync"

	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// catFeedDBHealth is the process-wide record of how the community store came
// up. Written once during startup and read by the diagnostics + metrics
// surfaces, so it is mutex-guarded rather than atomic-per-field: the readers
// need a consistent view across all of it.
type catFeedDBHealth struct {
	// Configured is false when no -cat-feed-db path is set (the feature is off
	// and every other field is meaningless).
	Configured bool
	// Available is true when the store opened and is serving lookups.
	Available bool
	// Path is the configured store directory.
	Path string
	// Detail is the operator-facing reason the store is unavailable, or the
	// recovery that was performed. Empty on a clean, unremarkable open.
	Detail string
	// Recovered is true when this boot moved a damaged store aside and
	// re-created it.
	Recovered bool
	// Quarantines counts damaged copies moved aside during this boot.
	Quarantines int
	// ResidualCopies is the number of `.corrupt.*` directories present after
	// the open — including any this boot created. Non-zero is the operator's
	// cue that there is disk to reclaim and an incident to reconcile.
	ResidualCopies int
}

var (
	catFeedDBHealthMu sync.RWMutex
	catFeedDBHealthy  catFeedDBHealth
)

// noteCatFeedDBState records the boot outcome for the community store.
func noteCatFeedDBState(h catFeedDBHealth) {
	catFeedDBHealthMu.Lock()
	catFeedDBHealthy = h
	catFeedDBHealthMu.Unlock()
}

// catFeedDBState returns a copy of the recorded boot outcome.
func catFeedDBState() catFeedDBHealth {
	catFeedDBHealthMu.RLock()
	defer catFeedDBHealthMu.RUnlock()
	return catFeedDBHealthy
}

// resetCatFeedDBHealthForTest clears the record. Test isolation only.
func resetCatFeedDBHealthForTest() {
	catFeedDBHealthMu.Lock()
	catFeedDBHealthy = catFeedDBHealth{}
	catFeedDBHealthMu.Unlock()
}

// checkCategoryFeedDB is the `category_feed_db` operator-contract row.
//
// Severity policy:
//   - not configured, or configured and healthy → ok.
//   - self-healed this boot, or unreconciled quarantined copies on disk → warn.
//     The gateway is serving correctly; the operator has evidence to inspect
//     and disk to reclaim.
//   - configured but unavailable → warn, never fail. Layer-1 categorisation is
//     still authoritative and the node is fully able to serve; a fail row here
//     would report a healthy gateway as broken.
func checkCategoryFeedDB() OperatorContractCheck {
	h := catFeedDBState()
	if !h.Configured {
		return OperatorContractCheck{
			Code:    "category_feed_db",
			Status:  diagOK,
			Message: "community category feed not configured",
		}
	}
	if !h.Available {
		return OperatorContractCheck{
			Code:           "category_feed_db",
			Status:         diagWarn,
			Message:        "community category store unavailable — category matching is running on the admin-managed list only",
			OperatorAction: "Check the data volume for the community category store (space, permissions, mount) and restart; see server logs for the cause.",
		}
	}
	if c, ok := checkCategoryFeedDeferral(); ok {
		return c
	}
	if h.Recovered {
		return OperatorContractCheck{
			Code:   "category_feed_db",
			Status: diagWarn,
			Message: fmt.Sprintf("community category store was damaged and re-created at startup (%d quarantined copy/copies on disk); the feed re-syncs automatically",
				h.ResidualCopies),
			OperatorAction: "Confirm the data volume is healthy, then delete the quarantined .corrupt.* copy to reclaim disk.",
		}
	}
	if h.ResidualCopies > 0 {
		return OperatorContractCheck{
			Code:   "category_feed_db",
			Status: diagWarn,
			Message: fmt.Sprintf("community category store is healthy, but %d quarantined copy/copies from an earlier incident remain on disk",
				h.ResidualCopies),
			OperatorAction: "Delete the quarantined .corrupt.* copy of the community category store to reclaim disk.",
		}
	}
	return OperatorContractCheck{
		Code:    "category_feed_db",
		Status:  diagOK,
		Message: "community category store loaded",
	}
}

// checkCategoryFeedDeferral reports a category sync the free-space guard
// deferred (internal/feedsync): below the floor, or free space that could not
// be measured. A bulk badger write onto a full filesystem SIGBUSes the
// process (readiness report F-DISK-1), so the write is not attempted; the row
// says which cause, and whether earlier data is serving or there is none yet.
func checkCategoryFeedDeferral() (OperatorContractCheck, bool) {
	sy := globalUT1FeedSyncer
	if sy == nil {
		return OperatorContractCheck{}, false
	}
	var cause string
	switch sy.Health().LastFailure {
	case feedsync.FailDiskSpace:
		cause = "the data filesystem is below the free-space floor for the write"
	case feedsync.FailDiskSpaceUnknown:
		cause = "free space on the data filesystem could not be measured"
	default:
		return OperatorContractCheck{}, false
	}
	coverage := "the previously synced community categories keep serving"
	if sy.StoreEmpty() {
		coverage = "no community category data is loaded yet — category matching uses the admin-managed list only"
	}
	return OperatorContractCheck{
		Code:           "category_feed_db",
		Status:         diagWarn,
		Message:        "community category sync deferred: " + cause + "; " + coverage,
		OperatorAction: "Free space on the filesystem holding the data volume (keep at least 2 GiB free), or fix why it cannot be measured; the sync retries on its own schedule.",
	}, true
}
