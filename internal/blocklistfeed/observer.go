package blocklistfeed

// observer.go — the sync observer seam, and the status seed used to drive the
// freshness plane's thresholds from a test without sleeping (CHAOS-123).
//
// # Why the seam exists
//
// CHAOS-108 fixed this feed's CADENCE and recorded the rest in the package
// doc as the open half: the feed had "no staleness alert or health row", so a
// deny control that had quietly stopped being refreshed was visible only as
// LastError on one admin panel and one log line per attempt.
//
// Package main owns that plane (blocklist_feed_health.go), because an alert
// type and a /metrics series are operator-facing contracts that live beside
// the other health planes, not inside a feed engine. What the engine owes it
// is a PUSH: an alert that can only be evaluated when somebody scrapes or
// opens the diagnostics page is not an alert. So the engine reports every
// completed round to an injected observer, exactly as internal/threatfeed
// does, and main's plane does the thresholding.
//
// # Why the outcome carries no cause
//
// SyncOutcome deliberately carries NO error text and NO feed URL. Both are
// unsafe for an egress sink by construction, and this round is not where that
// gets decided case by case:
//
//   - the feed URL is operator-configured and routinely embeds a token (the
//     reason diagnostics_blocklist_feed.go already refuses to print it);
//   - the error text embeds that URL, and for a transport failure also the
//     ephemeral local port — a per-attempt-unique value, which would defeat
//     the alert store's event+Detail dedup window by construction and evict
//     real alerts from the bounded retry queue. internal/threatfeed hit
//     exactly this and answered it with a BOUNDED reason class.
//
// A bounded reason class for this feed is the right follow-up and is recorded
// as one; it needs sentinel errors threaded through fetchFeedLines, which is a
// change to the fetch path rather than to the observability plane. Until then
// the alert says WHAT is stale and for how long, and the cause stays one
// role-gated API field (and one log line) away.

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// SyncOutcome is one completed round of one feed, delivered to the observer
// registered by SetSyncObserver.
//
// Fields are counts and times computed by this package. See the file comment
// for why no cause is carried.
type SyncOutcome struct {
	// OK is true when the round fetched and merged cleanly.
	OK bool
	// ConsecutiveFailures is the retry ladder's count after charging this
	// round: 0 on success.
	ConsecutiveFailures int
	// LastSync is this feed's last SUCCESSFUL sync after this round (zero =
	// it has still never succeeded).
	LastSync time.Time
	// Interval is the feed's configured auto-sync interval (0 = auto-sync
	// disabled, manual "Sync Now" only).
	Interval time.Duration
}

// syncObserver holds the registered observer. atomic.Pointer so a round never
// takes a lock to read it.
var syncObserver atomic.Pointer[func(SyncOutcome)]

// SetSyncObserver publishes the sync observer. A nil fn clears it.
//
// The observer MUST NOT call back into any Sync method, directly or
// transitively: it is invoked from inside the round, and the production
// observer only records state and fires an alert.
func SetSyncObserver(fn func(SyncOutcome)) {
	if fn == nil {
		syncObserver.Store(nil)
		return
	}
	syncObserver.Store(&fn)
}

// notifySyncObserver delivers an outcome, panic-contained.
//
// Containment is not decoration here. The observer is package main's alert and
// metric plane; without this recover a panic in it would be charged to the feed
// round by the scheduler's own obs.SafeCall, turning an observability bug into
// a feed that costs a tick and reports itself unhealthy. The plane that watches
// the feed must never be able to break the feed.
//
// Callers MUST NOT hold Syncer.mu: the observer reads the plane's own state and
// is free to call Feeds(), which takes the read lock, and sync.RWMutex is not
// reentrant against a waiting writer.
func notifySyncObserver(outcome SyncOutcome) {
	fn := syncObserver.Load()
	if fn == nil {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			obs.Warnf("BlocklistFeed: sync observer panicked (recovered): %s", obs.Sanitize(fmt.Sprint(v)))
		}
	}()
	(*fn)(outcome)
}

// SeedFeedStatusForTest overwrites one configured feed's status fields.
//
// Test support for the freshness plane: staleness is measured against 2x the
// feed's own interval, which defaults to 24 h, so the only alternative to this
// seam is sleeping past a day. Mirrors saasfeed.SeedStats, which exists for the
// same reason. Returns false when no such feed is configured.
//
// Production code never calls this; the status fields are owned by
// SyncFeedContext.
func (bs *Syncer) SeedFeedStatusForTest(feedURL string, lastSync, lastAttempt time.Time, lastError string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	st, ok := bs.feeds[feedURL]
	if !ok {
		return false
	}
	st.lastSync = lastSync
	st.lastAttempt = lastAttempt
	st.lastError = lastError
	return true
}
