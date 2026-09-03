package main

// threatfeed_health.go — CHAOS-57: the threat-intelligence feed's freshness
// contract.
//
// The threat feed is consulted on EVERY proxied request (CheckDomain) and
// additionally on every plain-HTTP one (CheckURL). Its content is the most
// perishable security data in the appliance: URLhaus and OpenPhish entries
// turn over on a scale of hours, so a feed frozen a week ago is not "slightly
// behind", it is a control that has quietly stopped working.
//
// Before this file, that degradation was INVISIBLE on every machine-readable
// surface:
//
//   - `/metrics` carried culvert_threat_feed_entries (a gauge of how many
//     entries are loaded). Because internal/threatfeed carries forward the
//     last-known-good table when a fetch fails — correct, and the fix for
//     WK-5 — that number does not move when syncing breaks. A frozen feed and
//     a healthy one publish the SAME series at the SAME value, indefinitely.
//     That is HA-17's shape: the fault is undetectable on the only surface a
//     Prometheus rule can read.
//   - `/healthz`, `/readyz` and `/api/diagnostics` carried nothing at all.
//   - The only report of sync health was `threat_feed_sync_ok` inside the
//     admin JSON blob at `/api/security-scan/status` — a human-polled surface
//     that no alerting rule consumes.
//
// The comparison that settles the severity is in-repo: the LESS security-
// critical feeds already have this plane. The signed SaaS feed has
// saas_feed_stale (saas_feed_alerts.go); the release catalog has
// release_catalog_stale plus culvert_release_catalog_expires_in_seconds
// (release_alerts.go); even the UT1 category feed publishes
// culvert_category_feed_last_sync_timestamp_seconds. The malware/phishing
// feed — the one on the request path — had strictly less than any of them.
//
// Surfaces added here, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the `threat_feed` operator-contract row.
//   - `/metrics` — culvert_threat_feed_{last_refresh_timestamp_seconds,
//     staleness_seconds,stale,sync_failures,sync_ok}.
//   - alerts — threat_feed_stale / threat_feed_sync_failing /
//     threat_feed_recovered, each fire-once-per-threshold-crossing.
//
// Deliberately NOT wired into /readyz. A node serving carried-forward threat
// intelligence is still enforcing policy, still scanning bodies, and still
// blocking every entry it holds; failing readiness would pull a working
// gateway out of a load-balancer rotation over a degraded feed and leave the
// traffic to egress with no gateway at all. Same judgement, and the same
// reasoning, as catfeeddb_health.go.

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// threatFeedStaleWindows is how many consecutive missed sync windows make
	// the feed stale. Expressed in WINDOWS rather than a fixed duration
	// because the interval is operator-configurable (-feed-sync-interval): a
	// fixed 24h threshold would be meaningless on a deployment that syncs
	// daily, and a deployment syncing hourly would wait a day to learn its
	// feed died.
	threatFeedStaleWindows = 4

	// threatFeedStaleFloor is the lower bound on the stale threshold. Without
	// it, a short interval (a test rig, or an operator syncing every 5
	// minutes) would page on 20 minutes of a public feed being slow — which
	// is ordinary, not an incident.
	threatFeedStaleFloor = 24 * time.Hour

	// threatFeedFailingThreshold is the number of CONSECUTIVE rounds that
	// fetched nothing before threat_feed_sync_failing fires. Matches the
	// release-catalog and SaaS-feed convention (3), so an operator learns one
	// number for all three planes.
	threatFeedFailingThreshold = 3
)

// threatFeedAlertFire is the emission seam (tests swap in a recorder). It
// routes through deferStartupAlert so a staleness alert raised during startup
// — before the webhook store has loaded — is queued rather than dropped.
var threatFeedAlertFire = deferStartupAlert

// threatFeedAlertLatch holds the once-per-crossing latches. Latches reset on
// restart, so restarting a stale appliance re-fires the alert once: accepted
// and documented, exactly as in release_alerts.go. Without the latch the
// engine's 30s dedup window would let a 6-hourly evaluation re-fire the same
// stale alert forever.
type threatFeedAlertLatch struct {
	mu      sync.Mutex
	stale   bool
	failing bool
}

var globalThreatFeedAlerts threatFeedAlertLatch

// threatFeedStaleAfter is the effective stale threshold for an interval.
func threatFeedStaleAfter(interval time.Duration) time.Duration {
	d := time.Duration(threatFeedStaleWindows) * interval
	if d < threatFeedStaleFloor {
		return threatFeedStaleFloor
	}
	return d
}

// threatFeedStatus is the derived freshness verdict: a pure function of the
// engine snapshot and the clock, so both the alert plane and the diagnostics
// row decide from exactly the same computation rather than two drifting
// copies of the same arithmetic.
type threatFeedStatus struct {
	// Reportable is false when the feed is not running (never Init'd, or
	// disabled) — every other field is meaningless and no surface should
	// claim a verdict. The CHAOS-54 rule: a "stale" reading on a node that
	// never had the feature is indistinguishable from a broken one.
	Reportable bool
	// NeverSynced is true when no round has ever brought in entries from any
	// source. This is NOT the same as stale: staleness is not computable from
	// a zero timestamp, and an appliance that has been up for two minutes on a
	// slow link has simply not finished yet.
	NeverSynced bool
	Stale       bool
	Failing     bool
	Age         time.Duration // since the last round that refreshed any source; 0 when NeverSynced
	StaleAfter  time.Duration
	Snapshot    threatFeedSnapshot
}

// threatFeedSnapshot mirrors the engine's FreshnessSnapshot in package main so
// the health plane can be tested without constructing a live Feed.
type threatFeedSnapshot struct {
	Enabled             bool
	Entries             int64
	LastAttempt         time.Time
	LastSuccess         time.Time
	LastRefresh         time.Time
	LastErr             string
	ConsecutiveFailures int
	SyncInterval        time.Duration
}

// evaluateThreatFeedStatus derives the verdict. Pure: no globals, no clock
// read, no locks.
func evaluateThreatFeedStatus(s threatFeedSnapshot, now time.Time) threatFeedStatus {
	st := threatFeedStatus{Snapshot: s, StaleAfter: threatFeedStaleAfter(s.SyncInterval)}
	if !s.Enabled {
		return st
	}
	st.Reportable = true
	st.Failing = s.ConsecutiveFailures >= threatFeedFailingThreshold
	// Age is measured from LastRefresh — the last round that brought in
	// entries from ANY source — not LastSuccess, which requires EVERY source
	// clean. One of two free public feeds 403ing indefinitely is an ordinary
	// steady state (it is exactly why ConsecutiveFailures is deliberately
	// narrow), and keying staleness on LastSuccess would report a feed whose
	// surviving source refreshes on every window as permanently stale, and
	// page about it. Codex review, PR #1264 — the two halves of this change
	// disagreed with each other until this was fixed.
	if s.LastRefresh.IsZero() {
		st.NeverSynced = true
		return st
	}
	// Clock rollback (NTP correcting a skewed appliance backwards) yields a
	// negative age. Clamp to zero rather than reporting a feed as fresh for
	// the size of the jump in one direction and stale in the other: the only
	// honest reading of "the last success is in the future" is "we have no
	// usable age", and the failing/never-synced signals still work.
	if age := now.Sub(s.LastRefresh); age > 0 {
		st.Age = age
		st.Stale = age >= st.StaleAfter
	}
	return st
}

// threatFeedSnapshotNow reads the live engine. Returns a zero (non-reportable)
// snapshot when the feed singleton is absent.
func threatFeedSnapshotNow() threatFeedSnapshot {
	if globalThreatFeed == nil {
		return threatFeedSnapshot{}
	}
	f := globalThreatFeed.Freshness()
	return threatFeedSnapshot{
		Enabled:             f.Enabled,
		Entries:             f.Entries,
		LastAttempt:         f.LastAttempt,
		LastSuccess:         f.LastSuccess,
		LastRefresh:         f.LastRefresh,
		LastErr:             f.LastErr,
		ConsecutiveFailures: f.ConsecutiveFailures,
		SyncInterval:        f.SyncInterval,
	}
}

// evaluateThreatFeedAlerts folds one status evaluation into the latched
// alerts. Wired as the engine's sync observer, so it runs after every sync
// round — scheduled, retried, or the admin's manual "sync now" — and once at
// startup when the boot round is skipped.
//
// Events are computed under the latch mutex and fired AFTER releasing it: the
// alert store's Dispatch is non-blocking, but firing under a lock is how a
// deadlock gets built later, and the CHAOS-50 cluster-CA defect is the
// standing example.
func evaluateThreatFeedAlerts() {
	evaluateThreatFeedAlertsAt(threatFeedSnapshotNow(), time.Now())
}

func evaluateThreatFeedAlertsAt(s threatFeedSnapshot, now time.Time) {
	st := evaluateThreatFeedStatus(s, now)
	events := func() []AlertPayload {
		globalThreatFeedAlerts.mu.Lock()
		defer globalThreatFeedAlerts.mu.Unlock()
		var out []AlertPayload
		out = append(out, globalThreatFeedAlerts.evalFailingLocked(st)...)
		out = append(out, globalThreatFeedAlerts.evalStaleLocked(st)...)
		return out
	}()
	for _, p := range events {
		threatFeedAlertFire(p.Event, p)
	}
}

// threatFeedAlertHost labels the alerts. The feed URLs are compile-time
// constants covering two upstreams, so naming one of them would be wrong half
// the time; a fixed subsystem label keeps Dispatch's `event + ":" + Detail`
// dedup key bounded, which is the WK-12 rule for any alert Detail.
const threatFeedAlertHost = "culvert-threat-feed"

func (l *threatFeedAlertLatch) evalFailingLocked(st threatFeedStatus) []AlertPayload {
	if !st.Reportable {
		return nil
	}
	if st.Failing {
		if l.failing {
			return nil
		}
		l.failing = true
		return []AlertPayload{{
			Event: "threat_feed_sync_failing", Host: threatFeedAlertHost, Source: "threatfeed",
			Detail: fmt.Sprintf("%d consecutive threat-feed sync rounds fetched nothing; serving last-known-good intelligence",
				st.Snapshot.ConsecutiveFailures),
		}}
	}
	if l.failing {
		l.failing = false
		return []AlertPayload{{
			Event: "threat_feed_recovered", Host: threatFeedAlertHost, Source: "threatfeed",
			Detail: "threat-feed sync recovered after repeated failures",
		}}
	}
	return nil
}

func (l *threatFeedAlertLatch) evalStaleLocked(st threatFeedStatus) []AlertPayload {
	if !st.Reportable {
		return nil
	}
	if st.Stale {
		if l.stale {
			return nil
		}
		l.stale = true
		return []AlertPayload{{
			Event: "threat_feed_stale", Host: threatFeedAlertHost, Source: "threatfeed",
			Detail: fmt.Sprintf("threat intelligence has not refreshed for %s (threshold %s); blocking on data that old is unreliable",
				st.Age.Round(time.Hour), st.StaleAfter.Round(time.Hour)),
		}}
	}
	if l.stale {
		l.stale = false
		return []AlertPayload{{
			Event: "threat_feed_recovered", Host: threatFeedAlertHost, Source: "threatfeed",
			Detail: "threat intelligence refreshed; feed is no longer stale",
		}}
	}
	return nil
}

// resetThreatFeedAlertsForTest clears the latches. Test isolation only.
func resetThreatFeedAlertsForTest() {
	globalThreatFeedAlerts.mu.Lock()
	globalThreatFeedAlerts.stale = false
	globalThreatFeedAlerts.failing = false
	globalThreatFeedAlerts.mu.Unlock()
}

// checkThreatFeed is the `threat_feed` operator-contract row.
//
// Severity policy, matching the file header's readiness reasoning:
//   - feed not running → ok (the feature is off; reporting it as degraded
//     would make every appliance without threat feeds look broken).
//   - never synced → warn. On a fresh appliance this clears within a minute;
//     if it persists it means the control has never been armed at all, which
//     is worth an operator's attention but is not a regression from a working
//     state.
//   - stale, or repeatedly failing → warn. Never fail: the node is serving
//     and enforcing, and a fail row would report a working gateway as broken.
//     The alert is the paging surface; this row is the explanation an
//     operator reads next.
func checkThreatFeed() OperatorContractCheck {
	return threatFeedContractRow(evaluateThreatFeedStatus(threatFeedSnapshotNow(), time.Now()))
}

// threatFeedContractRow is checkThreatFeed's pure core: no singleton, no clock
// read, so the severity policy is testable without a live feed.
func threatFeedContractRow(st threatFeedStatus) OperatorContractCheck {
	if !st.Reportable {
		return OperatorContractCheck{
			Code:    "threat_feed",
			Status:  diagOK,
			Message: "threat intelligence feed not enabled",
		}
	}
	if st.NeverSynced {
		return OperatorContractCheck{
			Code:           "threat_feed",
			Status:         diagWarn,
			Message:        "threat intelligence feed has never completed a sync — URL/domain threat blocking is running on whatever was restored from disk, if anything",
			OperatorAction: "Check outbound HTTPS egress to the threat-feed sources, then use Sync Now in the Security panel; server logs carry the fetch error.",
		}
	}
	if st.Stale {
		return OperatorContractCheck{
			Code:   "threat_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("threat intelligence last refreshed %s ago (stale after %s) — the feed is serving carried-forward entries",
				st.Age.Round(time.Hour), st.StaleAfter.Round(time.Hour)),
			OperatorAction: "Check outbound HTTPS egress to the threat-feed sources and the last sync error in the Security panel; the feed retries automatically and self-heals once reachable.",
		}
	}
	if st.Failing {
		return OperatorContractCheck{
			Code:   "threat_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("threat intelligence sync has fetched nothing for %d consecutive rounds; entries are still being served from the last good sync",
				st.Snapshot.ConsecutiveFailures),
			OperatorAction: "Check outbound HTTPS egress to the threat-feed sources; the feed retries on a bounded backoff and recovers on its own once reachable.",
		}
	}
	return OperatorContractCheck{
		Code:   "threat_feed",
		Status: diagOK,
		Message: fmt.Sprintf("threat intelligence current (%d entries, last refreshed %s ago)",
			st.Snapshot.Entries, st.Age.Round(time.Minute)),
	}
}

// threatFeedWritePrometheus appends the freshness series. Reads live state at
// scrape time; no hot-path cost.
//
// Every series is emitted ONLY when the feed is running. A
// `culvert_threat_feed_stale 0` on a node with no threat feed configured is
// indistinguishable from a healthy one, and the documented paging rule here is
// `== 1` — the CHAOS-54 rule about gauges that must not exist on a node which
// never had the subsystem.
func threatFeedWritePrometheus(w *strings.Builder) {
	writeThreatFeedMetricsAt(w, threatFeedSnapshotNow(), time.Now())
}

// writeThreatFeedMetricsAt is the pure core — same reason as
// threatFeedContractRow: the scrape output is what the defect gate compares,
// so it must be producible from a snapshot and a clock.
func writeThreatFeedMetricsAt(w *strings.Builder, snap threatFeedSnapshot, now time.Time) {
	st := evaluateThreatFeedStatus(snap, now)
	if !st.Reportable {
		return
	}
	stale, syncOK := 0, 0
	if st.Stale {
		stale = 1
	}
	// sync_ok requires a round to have ACTUALLY completed cleanly, not merely
	// the absence of a recorded error. On an enabled feed that has never
	// synced, LastErr starts empty, so keying on it alone published
	// `sync_ok 1` beside a zero last-refresh timestamp and a diagnostics row
	// reading "never synced" — a false healthy signal during every boot, and a
	// permanent one if the first fetch died before recording an error (Codex
	// review, PR #1264). Same rule as the absent-when-not-running gauges: an
	// unknown state must never render as the healthy value.
	if st.Snapshot.LastErr == "" && !st.Snapshot.LastSuccess.IsZero() {
		syncOK = 1
	}
	// staleness_seconds is the age of the DATA, which is what an alerting rule
	// wants; it is deliberately not derived from lastAttempt, because
	// lastAttempt advances on failures too and would report a permanently
	// broken feed as perpetually fresh (the trap SyncStatus's own comment
	// already warns about). Nor from lastSuccess — see evaluateThreatFeedStatus.
	fmt.Fprintf(w, `
# HELP culvert_threat_feed_last_refresh_timestamp_seconds Unix time of the last threat-feed sync that brought in entries from any source — the age of the served intelligence (0 = never)
# TYPE culvert_threat_feed_last_refresh_timestamp_seconds gauge
culvert_threat_feed_last_refresh_timestamp_seconds %d

# HELP culvert_threat_feed_staleness_seconds Age of the threat intelligence currently being served (seconds since the last sync that refreshed any source)
# TYPE culvert_threat_feed_staleness_seconds gauge
culvert_threat_feed_staleness_seconds %d

# HELP culvert_threat_feed_stale 1 when the served threat intelligence is older than the staleness threshold (four sync windows, floor 24h)
# TYPE culvert_threat_feed_stale gauge
culvert_threat_feed_stale %d

# HELP culvert_threat_feed_sync_failures Consecutive threat-feed sync rounds that fetched nothing from any source
# TYPE culvert_threat_feed_sync_failures gauge
culvert_threat_feed_sync_failures %d

# HELP culvert_threat_feed_sync_ok 1 when the most recent threat-feed sync fetched every source cleanly
# TYPE culvert_threat_feed_sync_ok gauge
culvert_threat_feed_sync_ok %d
`,
		unixOrZero(st.Snapshot.LastRefresh),
		int64(st.Age.Seconds()),
		stale,
		st.Snapshot.ConsecutiveFailures,
		syncOK,
	)
}
