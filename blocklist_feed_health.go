package main

// blocklist_feed_health.go — the operator-configured remote blocklist feed's
// freshness plane (CHAOS-123).
//
// # Why this file exists
//
// CHAOS-108 fixed this feed's cadence: a failed round no longer costs a full
// 24-hour interval, the fleet's phase is jittered, the fetch is cancellable,
// and a non-200 is no longer merged as if it were the feed. It then recorded
// the rest in internal/blocklistfeed's own package doc, in these words:
//
//	NOT fixed here, and recorded as the open half: this feed still has no
//	staleness alert or health row… Adding an alert type is an owner decision
//	with GUI/API parity consequences, not a drive-by rider on a scheduling
//	fix.
//
// This file is that decision. The gap matters for the same reason WK-5/CHAOS-59
// mattered for the threat feed, and the mechanism is identical:
//
//   - The feed is a DENY control. Its imports go through
//     blocklist.MergeFromLines, which is MERGE-ONLY and saves to disk, so a
//     feed that has not fetched for three weeks leaves the blocklist exactly
//     as large as a feed that fetched ten minutes ago. culvert_blocklist_size
//     is therefore NOT a freshness proxy — it is the metric that makes the
//     outage invisible. The gateway keeps enforcing yesterday's deny list and
//     every surface stays green.
//   - The destinations the operator added the feed to block are the exact
//     destinations the stale window fails OPEN on. That is not a degraded
//     cache; it is a control silently not being applied to new entries.
//
// What an operator had, measured at the claim revision: one WARN row in
// /api/diagnostics (diagnostics_blocklist_feed.go), gated on LastError != "",
// and one log line per failed attempt. NO /metrics series at all — so the
// enterprise monitoring path, Prometheus plus Alertmanager, could not see
// blocklist-feed freshness in any form — and no alert, so nothing paged. The
// one row that existed was also blind to the two shapes below.
//
// # The two shapes the LastError row could not see
//
// **A feed with auto-sync DISABLED that has never synced.** The admin API
// accepts `interval: "off"` (ui_policy.go blocklistFeedUpsert maps it to 0) and
// dueURLs skips `st.interval <= 0`, so the scheduler never attempts it. No
// attempt means no LastError, so the diagnostics row reports a green node while
// a configured deny control contributes nothing to the blocklist — not for an
// interval, but forever, until somebody clicks Sync Now. This plane reports it
// as its own WARN row and its own gauge, and deliberately does NOT page for it:
// the operator turned the schedule off, so paging would be paging on their
// configuration. The row is the part that was missing.
//
// **The window after a settings restore.** applyBlocklistFeeds (admin_settings.go)
// is authoritative over the startup seed and implements that as ClearFeeds()
// followed by SetFeed(), which constructs fresh feedStates — so a persistently
// failing feed's LastError, LastSync and ImportedCount are all reset to zero and
// the WARN row DISAPPEARS until the next round completes. It is a bounded window
// (nextAttempt is zero, so the feed is due on the next 60 s tick) and it is
// correctly bounded, but it is a window in which the only failure signal the
// product had reported "healthy". The never-synced gauge and row cover it.
//
// # What this file adds
//
// The shape threatfeed_health.go, syslog_health.go and storage_health.go use,
// and deliberately no new operator vocabulary beyond one alert event:
//
//   - /metrics — the culvert_blocklist_feed_* family, emitted only when at
//     least one feed is configured.
//   - /api/diagnostics — the existing `blocklist_feed` row, extended to the
//     never-synced and stale shapes.
//   - alerts — `blocklist_feed_stale`, fire-once per episode, recovered on
//     OBSERVED evidence (a clean round on every auto-sync feed), never on
//     elapsed time.
//
// # What it deliberately does NOT add
//
// **No per-feed labels on any series.** Every gauge here is an aggregate count
// or a worst-case age. A `{url=…}` label would put an operator-configured
// string — which routinely embeds a token, the reason the diagnostics row
// already refuses to print it — into a scrape endpoint that is commonly
// unauthenticated when metricsToken is unset, and would make cardinality a
// function of how many feeds an admin adds. The per-feed detail stays on the
// role-gated /api/blocklist/feed endpoint, which already carries it.
//
// **No /readyz row and no /healthz failure.** A node with a stale blocklist
// feed is a fully serving gateway: policy, categories, DPI, AV, CDR and the
// threat feed are unaffected, and the feed's already-imported entries are still
// enforced. Failing readiness would pull healthy gateways out of the load
// balancer over a third-party origin's outage — the same judgement
// threatfeed_health.go and catfeeddb_health.go both record.
//
// **No fail-closed toggle.** Blocking traffic because an operator's feed origin
// is unreachable would convert that origin's outage into the customer's outage,
// and this feed is an additive deny list on top of the policy engine's own
// default action — not the control that decides whether a request is allowed.
//
// **No durable last-success timestamp.** It would make freshness survive a
// restart (today lastSync is in-memory only: AdminSettings persists just the
// URL and interval, so every boot starts at "never synced" until the first
// round lands). It was considered and rejected for this round: the only durable
// store the feed set lives in is AdminSettings, which config versioning
// captures — a timestamp that advances on every successful sync would turn each
// round into an apparent configuration change. That belongs with the
// config-surface owner, and the residual risk is recorded in the review.

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklistfeed"
)

const (
	// blocklistFeedStaleFactor is how many of a feed's own configured
	// intervals of no successful sync make it STALE. Two, matching
	// threatFeedStaleFactor and the register's recommendation. Floored by
	// blocklistFeedStaleAfter for intervals near the scheduler tick.
	//
	// One interval would page on a single missed window, which is exactly the
	// transient CHAOS-108's backoff ladder exists to absorb: that ladder is
	// clamped to at most the interval, so by the time 2x has elapsed the feed
	// has already failed a run of bounded retries rather than one round.
	blocklistFeedStaleFactor = 2

	// blocklistFeedNeverSyncedGrace bounds the other staleness case: a feed
	// that has no successful sync to measure from. The age is measured from
	// the moment this plane was armed (process start) instead.
	//
	// Larger than threatFeedNeverSyncedGrace's 30 minutes would be wrong and
	// smaller would be noisy. The scheduler runs an immediate pass at Start
	// and then every 60 s, and a feed with no recorded attempt is due at once
	// (nextAttempt zero), so a reachable origin lands inside the first tick.
	// 15 minutes is many bounded retries later, and is also what covers the
	// post-restore window described above without firing inside it.
	blocklistFeedNeverSyncedGrace = 15 * time.Minute

	// blocklistFeedLogInterval rate-limits the staleness log line: the onset
	// immediately, then at most one line per interval, then one recovery line
	// naming the suppressed count. Same discipline as storage_health.go.
	blocklistFeedLogInterval = 30 * time.Minute
)

// blocklistFeedHealthRecord holds only what the feed engine cannot: the
// process-start anchor for the never-synced case, and the edge-triggered
// alert/log gates. Everything else is read live from blFeedSyncer.Feeds(), so
// there is one source of truth and no chance of the two drifting.
type blocklistFeedHealthRecord struct {
	mu sync.Mutex

	// armed is false until loadBlocklist runs. Every surface reports the
	// feature as absent then rather than exporting a zero that cannot be
	// told apart from "has never synced" — the CHAOS-54 rule.
	armed bool

	// startedAt anchors the never-synced staleness measurement.
	startedAt time.Time

	// alerted latches the stale alert for one episode, so a feed that stays
	// down does not re-page every round. Cleared by an OBSERVED clean round
	// on every auto-sync feed, or when feeds are removed from the monitored
	// configuration (noteBlocklistFeedsRemoved) — never by elapsed time.
	alerted bool

	// logAt / suppressed drive the rate-limited log line.
	logAt      time.Time
	suppressed int64
}

var blocklistFeedHealth blocklistFeedHealthRecord

// blocklistFeedNow is the clock seam. Tests drive staleness deterministically
// instead of sleeping past 48 hours.
var blocklistFeedNow = time.Now

// blocklistFeedSnapshots is the status source this plane reads: the feed
// engine's own read-only Feeds() snapshot in production.
//
// It is a seam so the root tests can present a feed whose last success was
// 13 hours ago without sleeping past a 24-hour threshold AND without the feed
// engine exporting a mutator for its own status fields. The engine's state is
// owned by its sync round; a test that wants a white-box view of that state
// belongs in internal/blocklistfeed. Read through blFeedSyncer at call time, so
// the nil-receiver contract (Feeds() on a nil syncer is empty) still applies.
var blocklistFeedSnapshots = func() []blocklistfeed.Feed { return blFeedSyncer.Feeds() }

// fireBlocklistFeedStaleAlert delivers the `blocklist_feed_stale` alert.
//
// Package-level seam so tests observe transitions synchronously rather than
// racing the process-global alerts sink. HasSubscriber-gated for the reason
// fireStorageWriteAlert documents: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a
// goroutine at all.
//
// The Detail carries counts, an age and an interval, all computed here. It
// carries NO feed URL and NO error text: the URL routinely embeds a token and
// the error embeds the URL, and Dispatch dedups on event+Detail, so a
// per-attempt-unique Detail would defeat the dedup window by construction. See
// internal/blocklistfeed/observer.go for the whole rule.
var fireBlocklistFeedStaleAlert = func(detail string) {
	if !alertStore().HasSubscriber("blocklist_feed_stale") {
		return
	}
	go fireAlert("blocklist_feed_stale", AlertPayload{
		Detail: detail,
		Source: "blocklistfeed",
	})
}

// noteBlocklistFeedConfigured arms the plane and installs the sync observer.
// Called from the blocklist startup slice, right after the scheduler starts.
func noteBlocklistFeedConfigured() {
	blocklistFeedHealth.mu.Lock()
	blocklistFeedHealth.armed = true
	blocklistFeedHealth.startedAt = blocklistFeedNow()
	blocklistFeedHealth.alerted = false
	blocklistFeedHealth.logAt = time.Time{}
	blocklistFeedHealth.suppressed = 0
	blocklistFeedHealth.mu.Unlock()

	blocklistfeed.SetSyncObserver(noteBlocklistFeedSync)
}

// noteBlocklistFeedSync is the sync observer: one call per completed round of
// one feed, success or failure.
//
// It must never call back into the syncer's Sync methods — see
// blocklistfeed.notifySyncObserver for why that rule is load-bearing rather
// than stylistic.
func noteBlocklistFeedSync(outcome blocklistfeed.SyncOutcome) {
	if outcome.OK {
		noteBlocklistFeedRoundRecovered()
		return
	}
	blocklistFeedHealth.mu.Lock()
	now := blocklistFeedNow()
	shouldLog := blocklistFeedHealth.logAt.IsZero() || now.Sub(blocklistFeedHealth.logAt) >= blocklistFeedLogInterval
	if shouldLog {
		blocklistFeedHealth.logAt = now
	} else {
		blocklistFeedHealth.suppressed++
	}
	blocklistFeedHealth.mu.Unlock()

	if shouldLog && logger != nil {
		logger.Printf("BlocklistFeed: round failed (%d consecutive) — the blocklist keeps its already-imported entries and is not being refreshed from this feed; retrying with backoff",
			outcome.ConsecutiveFailures)
	}
	evaluateBlocklistFeedStaleness()
}

// noteBlocklistFeedRoundRecovered clears the episode on OBSERVED evidence, and
// only once NO auto-sync feed is still stale.
//
// The second condition is what one clean round on one feed does not buy: a node
// with two feeds, one healthy and one dead, would otherwise clear the latch on
// every healthy round and re-fire on every dead one, paging in a loop. Elapsed
// time never clears it either — a feed that has stopped reporting failures
// because nothing is running looks identical to a healthy one, the mistake
// ca_health.go and storage_health.go both call out by name.
func noteBlocklistFeedRoundRecovered() {
	if snap := blocklistFeedState(); snap.StaleFeeds > 0 {
		return
	}
	blocklistFeedHealth.mu.Lock()
	wasAlerted := blocklistFeedHealth.alerted
	suppressed := blocklistFeedHealth.suppressed
	blocklistFeedHealth.alerted = false
	blocklistFeedHealth.logAt = time.Time{}
	blocklistFeedHealth.suppressed = 0
	blocklistFeedHealth.mu.Unlock()

	if wasAlerted && logger != nil {
		logger.Printf("BlocklistFeed: every auto-synced feed is fresh again (%d suppressed failure log lines during the episode)", suppressed)
	}
}

// noteBlocklistFeedsRemoved ends the current alert episode because feeds were
// removed from the monitored configuration: an admin delete (RemoveFeed) or a
// settings restore (ClearFeeds, then the persisted list re-added).
//
// The latch is otherwise cleared only by an observed clean round with nothing
// stale, and a removed feed never reports again. Without this, deleting the
// one feed that paged left the latch set, and a DIFFERENT feed that then
// failed from its first attempt was suppressed until some feed happened to
// sync cleanly or the process restarted — the new outage never paged.
//
// Ending the episode unconditionally, rather than only when nothing stale
// remains, is deliberate: the page that was sent described a feed set that no
// longer exists, and the cost is at most one re-page per operator removal for
// a feed that is still down, never a flapping loop. Any feed still stale pages
// again on its next failed round, with a Detail describing the current set.
func noteBlocklistFeedsRemoved() {
	blocklistFeedHealth.mu.Lock()
	wasAlerted := blocklistFeedHealth.alerted
	blocklistFeedHealth.alerted = false
	blocklistFeedHealth.logAt = time.Time{}
	blocklistFeedHealth.suppressed = 0
	blocklistFeedHealth.mu.Unlock()

	if wasAlerted && logger != nil {
		logger.Printf("BlocklistFeed: stale-feed alert episode ended because feeds were removed from the configuration; any feed that is still stale alerts again on its next failed round")
	}
}

// applyBlocklistFeedUpsert applies an admin feed upsert. Switching an auto-sync
// feed to manual (interval 0, "off") takes it out of the monitored set exactly
// as a removal does, so it ends the alert episode the same way: otherwise a
// latch set by that feed would suppress a different feed's later outage.
// Changing between two auto-sync intervals keeps the feed monitored and leaves
// the episode alone.
func applyBlocklistFeedUpsert(feedURL string, interval time.Duration) {
	wasAutoSync := false
	for _, f := range blFeedSyncer.Feeds() {
		if f.URL == feedURL {
			wasAutoSync = f.Interval > 0
			break
		}
	}
	blFeedSyncer.SetFeed(feedURL, interval)
	if wasAutoSync && interval == 0 {
		noteBlocklistFeedsRemoved()
	}
}

// evaluateBlocklistFeedStaleness fires the stale alert at most once per
// episode.
func evaluateBlocklistFeedStaleness() {
	snap := blocklistFeedState()
	if snap.StaleFeeds == 0 {
		return
	}
	blocklistFeedHealth.mu.Lock()
	alertNow := !blocklistFeedHealth.alerted
	blocklistFeedHealth.alerted = true
	blocklistFeedHealth.mu.Unlock()
	if !alertNow {
		return
	}
	fireBlocklistFeedStaleAlert(blocklistFeedAlertDetail(snap))
}

// blocklistFeedAlertDetail renders the bounded alert detail.
func blocklistFeedAlertDetail(snap blocklistFeedSnapshot) string {
	if snap.StaleNeverSyncedFeeds == snap.StaleFeeds {
		return fmt.Sprintf(
			"%d of %d auto-synced remote blocklist feed(s) have NEVER synced successfully on this node (%s since startup); those feeds contribute no entries at all, so the destinations they were added to block are not being blocked",
			snap.StaleNeverSyncedFeeds, snap.AutoSyncFeeds, snap.WorstAge.Round(time.Minute))
	}
	return fmt.Sprintf(
		"%d of %d auto-synced remote blocklist feed(s) are stale: the oldest successful sync was %s ago, over %dx its configured interval; the blocklist keeps its already-imported entries but is not receiving new ones",
		snap.StaleFeeds, snap.AutoSyncFeeds, snap.WorstAge.Round(time.Minute), blocklistFeedStaleFactor)
}

// blocklistFeedSnapshot is the derived view every surface reads.
type blocklistFeedSnapshot struct {
	// Armed is false until the startup slice ran.
	Armed bool
	// Feeds is every configured feed; AutoSyncFeeds is those with a positive
	// interval, and ManualOnlyFeeds the rest.
	Feeds           int
	AutoSyncFeeds   int
	ManualOnlyFeeds int
	// ManualOnlyNeverSynced counts manual-only feeds with no successful sync:
	// configured, contributing nothing, and never scheduled to try. Reported,
	// never alerted — see the file comment.
	ManualOnlyNeverSynced int
	// FailingFeeds is those whose most recent ATTEMPT failed. This is the
	// authoritative "is it broken right now" signal, and the one that
	// survives in the Feed snapshot across a round; ConsecutiveFailures does
	// not survive a restart.
	FailingFeeds int
	// NeverSyncedFeeds and StaleFeeds count AUTO-SYNC feeds only.
	// NeverSyncedFeeds includes feeds still inside the startup grace, so it is
	// NOT a subset of StaleFeeds; StaleNeverSyncedFeeds is the intersection
	// (never synced AND past the grace), the count that decides whether the
	// stale feeds are all never-synced ones.
	NeverSyncedFeeds      int
	StaleFeeds            int
	StaleNeverSyncedFeeds int
	// WorstAge is the largest age among auto-sync feeds: time since that
	// feed's last success, or since this plane was armed for one that has
	// never succeeded.
	WorstAge time.Duration
	// OldestSuccess is the earliest last-success among auto-sync feeds, and
	// is the zero time when any of them has never succeeded.
	OldestSuccess time.Time
	// MaxConsecutiveFailures is the largest ladder count among all feeds.
	MaxConsecutiveFailures int
}

// blocklistFeedState derives the current posture from the feed engine's own
// snapshot plus this file's process-start anchor.
//
// Split across three small accumulators rather than one loop body: the manual
// and auto-sync shapes answer different questions (see the file comment) and
// the per-feed arithmetic has its own clock-rollback rule, so folding them
// together put the function over the repository's cognitive-complexity gate
// and made the three policies hard to read as three policies.
func blocklistFeedState() blocklistFeedSnapshot {
	blocklistFeedHealth.mu.Lock()
	armed := blocklistFeedHealth.armed
	startedAt := blocklistFeedHealth.startedAt
	blocklistFeedHealth.mu.Unlock()

	snap := blocklistFeedSnapshot{Armed: armed}
	feeds := blocklistFeedSnapshots() // nil-receiver safe in production
	snap.Feeds = len(feeds)
	now := blocklistFeedNow()
	anyNeverSynced := false
	// The stale bound depends on how many feeds share a scheduler round, so it
	// is counted before any feed is measured.
	autoSync := 0
	for i := range feeds {
		if feeds[i].Interval > 0 {
			autoSync++
		}
	}

	for i := range feeds {
		f := &feeds[i]
		snap.accumulateAttempt(f)
		if f.Interval <= 0 {
			snap.accumulateManualOnly(f)
			continue
		}
		snap.AutoSyncFeeds++
		if f.LastSync.IsZero() {
			anyNeverSynced = true
		}
		snap.accumulateAutoSync(f, startedAt, now, autoSync)
	}
	if anyNeverSynced {
		// One feed with no success makes the fleet-wide "oldest success"
		// meaningless as a freshness floor; 0 is the documented sentinel and
		// is what the _never_synced gauge is read alongside.
		snap.OldestSuccess = time.Time{}
	}
	return snap
}

// accumulateAttempt folds in the per-feed signals that apply to every feed,
// scheduled or not.
//
// LastError, not ConsecutiveFailures == 0, is the authoritative "is it broken
// right now" signal: the ladder count is not persisted, so after a restart it
// reads zero for a feed that is known to be failing. Same rule
// internal/threatfeed's Health.LastRoundOK carries.
func (snap *blocklistFeedSnapshot) accumulateAttempt(f *blocklistfeed.Feed) {
	if f.LastError != "" {
		snap.FailingFeeds++
	}
	if f.ConsecutiveFailures > snap.MaxConsecutiveFailures {
		snap.MaxConsecutiveFailures = f.ConsecutiveFailures
	}
}

// accumulateManualOnly folds in a feed with no schedule. It is never stale and
// never alerted on: nothing was scheduled to make it fresh, so the only fact
// worth reporting is whether it has ever synced at all.
func (snap *blocklistFeedSnapshot) accumulateManualOnly(f *blocklistfeed.Feed) {
	snap.ManualOnlyFeeds++
	if f.LastSync.IsZero() {
		snap.ManualOnlyNeverSynced++
	}
}

// accumulateAutoSync folds in a scheduled feed: its age, the freshness floor it
// contributes, and whether it is stale against its OWN interval.
func (snap *blocklistFeedSnapshot) accumulateAutoSync(f *blocklistfeed.Feed, startedAt, now time.Time, autoSyncFeeds int) {
	if f.LastSync.IsZero() {
		snap.NeverSyncedFeeds++
		age := time.Duration(0)
		if !startedAt.IsZero() {
			age = now.Sub(startedAt)
		}
		snap.noteAge(age)
		if age >= blocklistFeedNeverSyncedGrace {
			snap.StaleFeeds++
			snap.StaleNeverSyncedFeeds++
		}
		return
	}
	if snap.OldestSuccess.IsZero() || f.LastSync.Before(snap.OldestSuccess) {
		snap.OldestSuccess = f.LastSync
	}
	age := now.Sub(f.LastSync)
	// A negative age means the clock moved backwards under us (an NTP step, a
	// VM restore). Report fresh rather than stale: the feed genuinely did
	// sync, and paging on a clock correction is noise — the same rule
	// threatFeedState applies.
	if age < 0 {
		age = 0
	}
	snap.noteAge(age)
	if age >= blocklistFeedStaleAfter(f.Interval, autoSyncFeeds) {
		snap.StaleFeeds++
	}
}

// blocklistFeedStaleAfter is how long an auto-sync feed may go without a
// successful sync before it reads stale: blocklistFeedStaleFactor intervals,
// but never less than the longest gap the scheduler gives a HEALTHY feed
// (blocklistfeed.MaxHealthyGap, for this node's autoSyncFeeds) plus one tick
// of margin for merging what was fetched.
//
// The floor matters only for short intervals. The admin API accepts any
// positive interval (a wire/config contract this plane does not narrow),
// while the scheduler fetches only on its tick, adds a stable jitter offset
// and fetches a round's due feeds one after another. So a 10 s feed is synced
// once per tick, a 60 s feed with positive jitter about 120 s apart, and six
// 60 s feeds that each take 29 s about 205 s apart. Against a bare 2x
// interval, feeds succeeding on every round they are given would read stale
// for part of each cycle and page a healthy node. For longer intervals 2x
// already clears that gap and the documented threshold is unchanged.
func blocklistFeedStaleAfter(interval time.Duration, autoSyncFeeds int) time.Duration {
	return max(time.Duration(blocklistFeedStaleFactor)*interval,
		blocklistfeed.MaxHealthyGap(interval, autoSyncFeeds)+blocklistfeed.TickInterval)
}

// noteAge keeps WorstAge at the largest age seen.
func (snap *blocklistFeedSnapshot) noteAge(age time.Duration) {
	if age > snap.WorstAge {
		snap.WorstAge = age
	}
}

// checkBlocklistFeeds returns the `blocklist_feed` operator-contract rows.
//
// Severity policy, in the order an operator should hear about them:
//   - no feed configured → no row. The feature is optional and a permanent row
//     would be noise on the deployments that do not use it.
//   - stale or never-synced auto-sync feed → WARN. Not fail: every other
//     control is intact, the already-imported entries are still enforced, and
//     the condition self-heals the moment the origin is reachable. The alert is
//     the paging surface; this row is the explanation read next.
//   - latest attempt failed → WARN, the pre-existing row, unchanged in wording.
//   - manual-only feed that has never synced → WARN, its own row, because the
//     operator action is different: nothing is broken, nothing will ever run.
//
// Report-only, and carrying counts only — never a feed URL (which may embed a
// token) or the raw error text.
func checkBlocklistFeeds() []OperatorContractCheck {
	snap := blocklistFeedState()
	if snap.Feeds == 0 {
		return nil
	}
	var rows []OperatorContractCheck

	if snap.StaleFeeds > 0 {
		msg := fmt.Sprintf("%d of %d auto-synced blocklist feed(s) are stale — the oldest successful sync was %s ago (over %dx its configured interval); the blocklist keeps its already-imported entries but is not receiving new ones",
			snap.StaleFeeds, snap.AutoSyncFeeds, snap.WorstAge.Round(time.Minute), blocklistFeedStaleFactor)
		if snap.StaleNeverSyncedFeeds == snap.StaleFeeds {
			msg = fmt.Sprintf("%d of %d auto-synced blocklist feed(s) have NEVER synced successfully on this node (%s since startup) — those feeds contribute no entries at all, so the destinations they were added to block are not being blocked",
				snap.StaleNeverSyncedFeeds, snap.AutoSyncFeeds, snap.WorstAge.Round(time.Minute))
		}
		rows = append(rows, OperatorContractCheck{
			Code:           "blocklist_feed",
			Status:         diagWarn,
			Message:        msg,
			OperatorAction: "Check outbound HTTPS reachability to the feed origins from this node (including any upstream proxy), then open Policy → Blocklist → Feeds and use Sync Now to confirm recovery; the feed also retries automatically with backoff.",
		})
	}

	if snap.FailingFeeds > 0 {
		rows = append(rows, OperatorContractCheck{
			Code:   "blocklist_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("%d of %d blocklist feed(s) failed their latest sync — "+
				"the blocklist is not being refreshed from them and keeps its last imported entries", snap.FailingFeeds, snap.Feeds),
			OperatorAction: "Open Policy → Blocklist → Feeds, check the Last Error column for each feed, correct the URL or network path, then use Sync Now to confirm recovery.",
		})
	}

	if snap.ManualOnlyNeverSynced > 0 {
		rows = append(rows, OperatorContractCheck{
			Code:   "blocklist_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("%d of %d blocklist feed(s) have auto-sync turned off and have never been synced — they are configured but contribute nothing to the blocklist, and nothing will sync them automatically",
				snap.ManualOnlyNeverSynced, snap.Feeds),
			OperatorAction: "Open Policy → Blocklist → Feeds and either use Sync Now for each one or set a sync interval so the scheduler keeps it refreshed.",
		})
	}
	return rows
}

// blocklistFeedWritePrometheus appends the culvert_blocklist_feed_* series.
//
// Emitted ONLY when at least one feed is configured. An unconditional
// culvert_blocklist_feed_sync_ok 0 on a node that never configured a feed is
// indistinguishable from a node whose feed is broken, and the documented
// paging rule is `== 0` — so emitting it always would page every deployment
// that does not use the feature. Same rule as the SOCKS5, cluster-CA and
// threat-feed gauges.
//
// No series carries a label. See the file comment for why per-feed labels are
// refused on this endpoint.
func blocklistFeedWritePrometheus(w *strings.Builder) {
	snap := blocklistFeedState()
	if !snap.Armed || snap.Feeds == 0 {
		return
	}

	w.WriteString("\n# HELP culvert_blocklist_feed_configured Remote blocklist feeds configured on this node\n")
	w.WriteString("# TYPE culvert_blocklist_feed_configured gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_configured %d\n", snap.Feeds)

	w.WriteString("\n# HELP culvert_blocklist_feed_autosync_enabled Remote blocklist feeds with a positive sync interval (the rest are manual Sync Now only)\n")
	w.WriteString("# TYPE culvert_blocklist_feed_autosync_enabled gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_autosync_enabled %d\n", snap.AutoSyncFeeds)

	w.WriteString("\n# HELP culvert_blocklist_feed_manual_never_synced Configured blocklist feeds with auto-sync off that have never synced, so they contribute no entries and nothing will sync them\n")
	w.WriteString("# TYPE culvert_blocklist_feed_manual_never_synced gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_manual_never_synced %d\n", snap.ManualOnlyNeverSynced)

	w.WriteString("\n# HELP culvert_blocklist_feed_failing Blocklist feeds whose most recent sync attempt failed\n")
	w.WriteString("# TYPE culvert_blocklist_feed_failing gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_failing %d\n", snap.FailingFeeds)

	w.WriteString("\n# HELP culvert_blocklist_feed_never_synced Auto-synced blocklist feeds that have never completed a successful sync on this node\n")
	w.WriteString("# TYPE culvert_blocklist_feed_never_synced gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_never_synced %d\n", snap.NeverSyncedFeeds)

	w.WriteString("\n# HELP culvert_blocklist_feed_stale Auto-synced blocklist feeds with no successful sync for over 2x their configured interval (or never, past the startup grace)\n")
	w.WriteString("# TYPE culvert_blocklist_feed_stale gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_stale %d\n", snap.StaleFeeds)

	// The age is exported as well as the timestamp: the never-synced case has
	// no timestamp to subtract from, and that is precisely the case an
	// operator most needs to alert on.
	w.WriteString("\n# HELP culvert_blocklist_feed_stale_seconds Age of the oldest auto-synced blocklist feed (seconds since its last successful sync, or since startup when it has never succeeded)\n")
	w.WriteString("# TYPE culvert_blocklist_feed_stale_seconds gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_stale_seconds %d\n", int64(snap.WorstAge.Seconds()))

	w.WriteString("\n# HELP culvert_blocklist_feed_oldest_success_timestamp_seconds Unix time of the oldest last-successful sync among auto-synced blocklist feeds (0 = at least one has never synced)\n")
	w.WriteString("# TYPE culvert_blocklist_feed_oldest_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_oldest_success_timestamp_seconds %d\n", unixOrZero(snap.OldestSuccess))

	w.WriteString("\n# HELP culvert_blocklist_feed_sync_ok 1 when every configured blocklist feed's latest attempt succeeded and none is stale, 0 otherwise\n")
	w.WriteString("# TYPE culvert_blocklist_feed_sync_ok gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_sync_ok %d\n", boolGauge(snap.FailingFeeds == 0 && snap.StaleFeeds == 0))

	w.WriteString("\n# HELP culvert_blocklist_feed_consecutive_sync_failures Largest consecutive-failure count across blocklist feeds since each last synced cleanly (not persisted across restart)\n")
	w.WriteString("# TYPE culvert_blocklist_feed_consecutive_sync_failures gauge\n")
	fmt.Fprintf(w, "culvert_blocklist_feed_consecutive_sync_failures %d\n", snap.MaxConsecutiveFailures)
}

// resetBlocklistFeedHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so replacing it wholesale under the lock
// would swap the held mutex for an unlocked zero value.
func resetBlocklistFeedHealthForTest() {
	blocklistFeedHealth.mu.Lock()
	blocklistFeedHealth.armed = false
	blocklistFeedHealth.startedAt = time.Time{}
	blocklistFeedHealth.alerted = false
	blocklistFeedHealth.logAt = time.Time{}
	blocklistFeedHealth.suppressed = 0
	blocklistFeedHealth.mu.Unlock()
	blocklistFeedNow = time.Now
	blocklistfeed.SetSyncObserver(nil)
}
