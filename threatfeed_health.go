package main

// threatfeed_health.go — the threat-intelligence feed's staleness plane.
//
// # Why this file exists
//
// The register has carried WK-5 since the first sweep. Its first half — a
// partially-failed sync unconditionally replacing the lookup tables with only
// what succeeded, wiping the rest of the threat database in memory AND on disk
// — was closed by the per-source carry-forward in internal/threatfeed's
// applySync. That fix is correct and stays.
//
// It also removed the only signal an operator had.
//
// Before carry-forward, a feed outage was catastrophic but LOUD in the one
// place a Prometheus rule can read: culvert_threat_feed_entries collapsed
// toward zero. After it, the entry count is held at its last-good value by
// design, so a node whose feed has not fetched successfully in three weeks
// exports byte-identical metrics to a node that synced ten minutes ago. The
// only surviving difference reached ONE role-gated admin JSON field
// (threat_feed_sync_ok, security_scan.go), which no alerting rule scrapes.
//
// That is the §1 silent-degradation theme in its purest form: a security
// control quietly stops being refreshed, the dashboard stays green, and the
// gateway keeps enforcing against intelligence that is arbitrarily old. Threat
// intel is the one control whose whole value is freshness — a URLhaus entry is
// useful because it was added hours ago, and yesterday's list does not contain
// today's campaign.
//
// Two more facts make the window wider than it looks:
//
//   - Until the companion change in internal/threatfeed, a failed round was not
//     retried until the next FULL interval (6 h). One transient fault on the
//     customer's egress path bought six hours of frozen intelligence.
//   - `Start` performs an immediate sync when the on-disk DB is empty. A fresh
//     or re-imaged node whose FIRST sync fails therefore enforces with NO
//     threat intelligence — not stale, none — and reports itself healthy
//     throughout.
//
// # What this file adds
//
// The same shape storage_health.go, ca_health.go and socks5_health.go use, and
// deliberately no new operator vocabulary:
//
//   - /metrics — culvert_threat_feed_last_success_timestamp_seconds,
//     _stale_seconds, _sync_ok, _sync_failures_total, _consecutive_failures.
//   - /api/diagnostics — the `threat_feed` operator-contract row.
//   - alerts — `threat_feed_stale`, fire-once per episode, recovered on
//     OBSERVED evidence (a clean round), never on elapsed time.
//
// # What it deliberately does NOT add
//
// **No /readyz row, and no /healthz failure.** A node with stale threat intel
// is a fully serving gateway: policy, category, DPI, AV and CDR are all
// unaffected, and the feed's own entries are still enforced. Failing readiness
// would pull healthy gateways out of the load balancer over a degraded cache —
// the same judgement catfeeddb_health.go records for the community category
// store, and for the same reason. Staleness is a WARN row and an alert, not an
// ejection.
//
// **No fail-closed toggle.** Blocking traffic because a third-party feed is
// unreachable would convert a provider's outage into the customer's outage,
// and the threat feed is an additive deny-list on top of default-deny policy —
// not the control that decides whether a request is allowed.

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

const (
	// threatFeedStaleFactor is how many sync intervals of no successful sync
	// make the feed STALE. Two intervals, matching the register's own
	// recommendation ("staleness alert at >2× interval").
	//
	// One interval would page on a single missed window, which is exactly the
	// transient the new backoff exists to absorb — the retry ladder reaches its
	// 1 h ceiling long before 2× 6 h elapses, so by the time this fires the
	// feed has already failed a dozen bounded retries. That is no longer a
	// blip.
	threatFeedStaleFactor = 2

	// threatFeedNeverSyncedGrace bounds the OTHER staleness case: a node that
	// has never had a successful sync at all. There is no last-success to
	// measure from, so the age is measured from process start instead. Kept
	// well below one sync interval because this is the severe shape — the node
	// is enforcing with an empty or import-only threat database, and an
	// operator should hear about it in minutes, not hours.
	threatFeedNeverSyncedGrace = 30 * time.Minute

	// threatFeedLogInterval rate-limits the staleness log line: the onset
	// immediately, then at most one line per interval, then one recovery line
	// naming the suppressed count. Same discipline as storage_health.go — the
	// log carries the SIGNAL, the counter carries the MAGNITUDE.
	threatFeedLogInterval = 30 * time.Minute
)

// threatFeedHealth is the process-wide record of the feed's sync health.
//
// It holds only what the feed itself cannot: the process-start reference for
// the never-synced case, and the edge-triggered alert/log gates. Everything
// else (last success, failure counts, the bounded reason class) is read live
// from internal/threatfeed's own Health snapshot, so there is exactly one
// source of truth and no chance of the two drifting.
type threatFeedHealthRecord struct {
	mu sync.Mutex

	// configured is false until the threat feed is started. Every surface
	// reports the feature as absent then, rather than exporting a zero that is
	// indistinguishable from "has never synced" — the CHAOS-54 rule.
	configured bool

	// startedAt anchors the never-synced staleness measurement.
	startedAt time.Time

	// alerted latches the stale alert for the duration of one episode, so a
	// feed that stays down does not re-page every round. Cleared only by an
	// OBSERVED clean sync.
	alerted bool

	// logAt / suppressed drive the rate-limited log line.
	logAt      time.Time
	suppressed int64
}

var threatFeedHealth threatFeedHealthRecord

// threatFeedNow is the clock seam. Tests drive staleness deterministically
// instead of sleeping past a 12-hour threshold.
var threatFeedNow = time.Now

// fireThreatFeedStaleAlert delivers the `threat_feed_stale` alert.
//
// Package-level seam so tests observe transitions synchronously rather than
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches). HasSubscriber-gated for the reason documented on
// fireStorageWriteAlert: with no webhook configured — the default posture, and
// the state of every test binary — this must not spawn a goroutine at all.
//
// The Detail carries the BOUNDED reason class from internal/threatfeed, never
// the verbose error summary: Dispatch dedups on event+Detail, and the summary
// embeds the feed URL and (for a transport failure) the ephemeral local port,
// so a per-attempt-unique Detail would defeat the dedup window by construction
// and evict real threat alerts from the 500-entry retry queue. The verbose
// cause stays on the role-gated admin API and in the log.
var fireThreatFeedStaleAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("threat_feed_stale") {
		return
	}
	go fireAlert("threat_feed_stale", AlertPayload{
		Detail: detail,
		Source: "threatfeed",
	})
}

// noteThreatFeedConfigured records that the threat feed was started, and
// installs the sync observer. Called from the scanning startup slice.
func noteThreatFeedConfigured() {
	threatFeedHealth.mu.Lock()
	threatFeedHealth.configured = true
	threatFeedHealth.startedAt = threatFeedNow()
	threatFeedHealth.alerted = false
	threatFeedHealth.logAt = time.Time{}
	threatFeedHealth.suppressed = 0
	threatFeedHealth.mu.Unlock()

	threatfeed.SetSyncObserver(noteThreatFeedSync)
}

// noteThreatFeedSync is the sync observer: one call per completed round,
// success or failure.
//
// It must never call back into the feed (directly or transitively) — see
// notifySyncObserver, and the same rule audit.SetWriteFailureObserver carries
// for the same reason.
func noteThreatFeedSync(outcome threatfeed.SyncOutcome) {
	if outcome.OK {
		noteThreatFeedSyncRecovered()
		return
	}
	threatFeedHealth.mu.Lock()
	now := threatFeedNow()
	shouldLog := threatFeedHealth.logAt.IsZero() || now.Sub(threatFeedHealth.logAt) >= threatFeedLogInterval
	if shouldLog {
		threatFeedHealth.logAt = now
	} else {
		threatFeedHealth.suppressed++
	}
	threatFeedHealth.mu.Unlock()

	if shouldLog && logger != nil {
		logger.Printf("ThreatFeed: sync failed (sources=%q, %d consecutive) — serving last-known-good intelligence; retrying with backoff",
			sanitizeLog(outcome.FailedSources), outcome.ConsecutiveFailures)
	}
	evaluateThreatFeedStaleness()
}

// noteThreatFeedSyncRecovered clears the episode on OBSERVED evidence — one
// round in which every feed fetched cleanly.
//
// Elapsed time never clears it. A feed that has stopped reporting failures
// because nothing is running looks identical to a healthy one, which is the
// mistake ca_health.go and storage_health.go both call out by name.
func noteThreatFeedSyncRecovered() {
	threatFeedHealth.mu.Lock()
	wasAlerted := threatFeedHealth.alerted
	suppressed := threatFeedHealth.suppressed
	threatFeedHealth.alerted = false
	threatFeedHealth.logAt = time.Time{}
	threatFeedHealth.suppressed = 0
	threatFeedHealth.mu.Unlock()

	if wasAlerted && logger != nil {
		logger.Printf("ThreatFeed: sync recovered — intelligence is fresh again (%d suppressed failure log lines during the episode)", suppressed)
	}
}

// evaluateThreatFeedStaleness fires the stale alert at most once per episode.
func evaluateThreatFeedStaleness() {
	snap := threatFeedState()
	if !snap.Stale {
		return
	}
	threatFeedHealth.mu.Lock()
	alertNow := !threatFeedHealth.alerted
	threatFeedHealth.alerted = true
	threatFeedHealth.mu.Unlock()
	if !alertNow {
		return
	}
	if snap.NeverSynced {
		fireThreatFeedStaleAlert(fmt.Sprintf(
			"threat intelligence has NEVER synced successfully on this node (%s since startup, failing sources: %s); the gateway is enforcing with no threat-feed coverage",
			snap.Age.Round(time.Minute), reasonOrUnknown(snap.FailedSources)))
		return
	}
	fireThreatFeedStaleAlert(fmt.Sprintf(
		"threat intelligence has not synced successfully for %s (over %dx the %s sync interval, failing sources: %s); the gateway is enforcing against stale intelligence",
		snap.Age.Round(time.Minute), threatFeedStaleFactor, snap.SyncInterval, reasonOrUnknown(snap.FailedSources)))
}

// reasonOrUnknown renders the bounded reason class, defending against an empty
// value (a feed that has never attempted a round has no failed sources yet).
func reasonOrUnknown(reason string) string {
	if reason == "" {
		return "unknown"
	}
	return reason
}

// threatFeedSnapshot is the derived view every surface reads.
type threatFeedSnapshot struct {
	Configured  bool
	NeverSynced bool
	Stale       bool
	// Age is the time since the last successful sync, or since process start
	// when there has never been one.
	Age                 time.Duration
	LastSuccess         time.Time
	SyncInterval        time.Duration
	ConsecutiveFailures int
	TotalFailures       int64
	FailedSources       string
	ErrSummary          string
	Entries             int64
}

// threatFeedState derives the current posture from the feed's own health
// snapshot plus this file's process-start anchor.
func threatFeedState() threatFeedSnapshot {
	threatFeedHealth.mu.Lock()
	configured := threatFeedHealth.configured
	startedAt := threatFeedHealth.startedAt
	threatFeedHealth.mu.Unlock()

	snap := threatFeedSnapshot{Configured: configured}
	if !configured || globalThreatFeed == nil {
		return snap
	}
	h := globalThreatFeed.Health()
	snap.LastSuccess = h.LastSuccess
	snap.SyncInterval = h.SyncInterval
	snap.ConsecutiveFailures = h.ConsecutiveFailures
	snap.TotalFailures = h.TotalFailures
	snap.FailedSources = h.FailedSources
	snap.ErrSummary = h.ErrSummary
	snap.Entries = h.Entries

	now := threatFeedNow()
	if h.LastSuccess.IsZero() {
		snap.NeverSynced = true
		if !startedAt.IsZero() {
			snap.Age = now.Sub(startedAt)
		}
		snap.Stale = snap.Age >= threatFeedNeverSyncedGrace
		return snap
	}
	snap.Age = now.Sub(h.LastSuccess)
	// A negative age means the clock moved backwards under us (NTP step, VM
	// restore). Report fresh rather than stale: the feed genuinely did sync,
	// and paging on a clock correction is noise.
	if snap.Age < 0 {
		snap.Age = 0
	}
	if h.SyncInterval > 0 {
		snap.Stale = snap.Age >= time.Duration(threatFeedStaleFactor)*h.SyncInterval
	}
	return snap
}

// checkThreatFeed is the `threat_feed` operator-contract row.
//
// Severity policy:
//   - not configured → ok. The feed is optional; a permanent row would be noise
//     on a deployment that does not run it.
//   - never synced → WARN, not fail. The node is enforcing with no threat-feed
//     coverage, which is serious — but every other control is intact and the
//     condition self-heals the moment the origin is reachable, so a fail row
//     (which operators wire to page and to eject) overstates it. The alert is
//     the paging surface; this row is the explanation an operator reads next.
//   - stale beyond the factor → warn, naming the age and the failing sources.
//   - healthy → ok, carrying the cumulative failure count so a HISTORY of
//     transient failures stays visible after recovery.
func checkThreatFeed() OperatorContractCheck {
	snap := threatFeedState()
	if !snap.Configured {
		return OperatorContractCheck{
			Code:    "threat_feed",
			Status:  diagOK,
			Message: "Threat feed not configured",
		}
	}
	if snap.NeverSynced {
		if !snap.Stale {
			return OperatorContractCheck{
				Code:    "threat_feed",
				Status:  diagOK,
				Message: "Threat feed starting up — first sync has not completed yet",
			}
		}
		return OperatorContractCheck{
			Code:   "threat_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("Threat feed has NEVER synced successfully (%s since startup, %d failed attempts, failing sources: %s); this node is enforcing with no threat-feed coverage",
				snap.Age.Round(time.Minute), snap.TotalFailures, reasonOrUnknown(snap.FailedSources)),
			OperatorAction: "Check outbound HTTPS reachability to urlhaus.abuse.ch and openphish.com from this node (including any upstream proxy), then use the admin Security panel's manual sync to retry immediately.",
		}
	}
	if snap.Stale {
		return OperatorContractCheck{
			Code:   "threat_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("Threat feed last synced successfully %s ago (over %dx the %s interval, %d consecutive failures, failing sources: %s); enforcement continues against last-known-good intelligence",
				snap.Age.Round(time.Minute), threatFeedStaleFactor, snap.SyncInterval, snap.ConsecutiveFailures, reasonOrUnknown(snap.FailedSources)),
			OperatorAction: "Check outbound HTTPS reachability to the feed origins from this node; the feed retries automatically with backoff and recovers without intervention once they are reachable.",
		}
	}
	if snap.TotalFailures > 0 {
		return OperatorContractCheck{
			Code:   "threat_feed",
			Status: diagOK,
			Message: fmt.Sprintf("Threat feed fresh (%d entries, last success %s ago, %d transient sync failures since startup)",
				snap.Entries, snap.Age.Round(time.Minute), snap.TotalFailures),
		}
	}
	return OperatorContractCheck{
		Code:   "threat_feed",
		Status: diagOK,
		Message: fmt.Sprintf("Threat feed fresh (%d entries, last success %s ago)",
			snap.Entries, snap.Age.Round(time.Minute)),
	}
}

// threatFeedWritePrometheus appends the culvert_threat_feed_* freshness series.
//
// Every series here is emitted ONLY when the feed is configured. A
// `culvert_threat_feed_sync_ok 0` on a node that never ran the feed is
// indistinguishable from a node whose feed is broken, and the documented
// paging rule is `== 0` — so an unconditional gauge would page every
// deployment that does not use the feature. Same rule as the SOCKS5 and
// cluster-CA gauges.
func threatFeedWritePrometheus(w *strings.Builder) {
	snap := threatFeedState()
	if !snap.Configured {
		return
	}

	w.WriteString("\n# HELP culvert_threat_feed_last_success_timestamp_seconds Unix time of the last fully-successful threat feed sync (0 = never)\n")
	w.WriteString("# TYPE culvert_threat_feed_last_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_threat_feed_last_success_timestamp_seconds %d\n", unixOrZero(snap.LastSuccess))

	// The age is exported directly as well as the timestamp: the never-synced
	// case has no timestamp to subtract from, and that is precisely the case an
	// operator most needs to alert on.
	w.WriteString("\n# HELP culvert_threat_feed_stale_seconds Age of the threat intelligence (seconds since the last successful sync, or since startup when it has never succeeded)\n")
	w.WriteString("# TYPE culvert_threat_feed_stale_seconds gauge\n")
	fmt.Fprintf(w, "culvert_threat_feed_stale_seconds %d\n", int64(snap.Age.Seconds()))

	w.WriteString("\n# HELP culvert_threat_feed_sync_ok 1 when the most recent threat feed sync fetched every source cleanly, 0 otherwise\n")
	w.WriteString("# TYPE culvert_threat_feed_sync_ok gauge\n")
	fmt.Fprintf(w, "culvert_threat_feed_sync_ok %d\n", boolGauge(snap.ConsecutiveFailures == 0))

	w.WriteString("\n# HELP culvert_threat_feed_sync_failures_total Threat feed sync rounds in which at least one source did not fetch cleanly\n")
	w.WriteString("# TYPE culvert_threat_feed_sync_failures_total counter\n")
	fmt.Fprintf(w, "culvert_threat_feed_sync_failures_total %d\n", snap.TotalFailures)

	w.WriteString("\n# HELP culvert_threat_feed_consecutive_sync_failures Threat feed sync rounds failed since the last clean one\n")
	w.WriteString("# TYPE culvert_threat_feed_consecutive_sync_failures gauge\n")
	fmt.Fprintf(w, "culvert_threat_feed_consecutive_sync_failures %d\n", snap.ConsecutiveFailures)
}

// resetThreatFeedHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so replacing it wholesale under the lock
// would swap the held mutex for an unlocked zero value.
func resetThreatFeedHealthForTest() {
	threatFeedHealth.mu.Lock()
	threatFeedHealth.configured = false
	threatFeedHealth.startedAt = time.Time{}
	threatFeedHealth.alerted = false
	threatFeedHealth.logAt = time.Time{}
	threatFeedHealth.suppressed = 0
	threatFeedHealth.mu.Unlock()
	threatFeedNow = time.Now
	threatfeed.SetSyncObserver(nil)
}
