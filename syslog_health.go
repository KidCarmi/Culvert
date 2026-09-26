package main

// syslog_health.go — the SIEM/syslog forwarding feed's delivery plane
// (CHAOS-72).
//
// # Why this file exists
//
// `internal/syslog` carries the customer's SECURITY RECORD off the box: every
// `auditEvent` (store.go `globalSyslog.WriteAudit`) and every request-log entry
// (`globalSyslog.WriteRequest`). For a great many enterprises the SIEM is the
// record of RECORD — the local JSONL file is rotated at 50 MB with one archive
// and is never collected — so a collector that stops receiving is a hole in the
// compliance trail, not a monitoring inconvenience. That is the CWE-778 /
// A09:2021 class `internal/audit`'s own header names, and the class CHAOS-61
// closed for the DP→CP audit push queue with the recorded reasoning that a
// queue "dropped with no counter, metric or log line".
//
// The syslog feed was three hundred lines below that same contract.
//
//   - `Drops()` reached EXACTLY ONE consumer in the whole tree: `GET
//     /api/syslog`, an admin-only JSON blob. No Prometheus series, so no
//     alerting rule could exist. No `/healthz` field, where its two siblings
//     (`auditLogWriteErrors`, `auditClusterPushDrops`) both report. No alert.
//     No log line — the drain goroutine drops silently, by construction.
//
//   - The one operator-contract row that exists, `syslog_feed`, is a pure
//     function of two strings set ONCE at init (`globalSyslog == nil ||
//     syslogConfigured != syslogConfiguredAddr`) and never consults delivery at
//     all. It was built for the boot-time connect failure, which is real but
//     narrow — the collector has to be down in the exact window the proxy
//     starts. The common case is the collector going away during weeks of
//     uptime, and for that case the row returned `ok` with the message
//     **"remote syslog/SIEM forwarding is active"**. Measured against the
//     pre-fix tree: 49 of 49 audit lines dropped, row still `ok`, still
//     "active". A health surface asserting a false statement is worse than no
//     surface, because it is the one an auditor is shown.
//
//   - Even the admin blob could not answer the question. `Drops()` is
//     CUMULATIVE with no time axis: `drops: 40213` cannot distinguish a feed
//     that is dark right now from one that healed last Tuesday. CHAOS-59
//     settled that shape for the threat feed — freshness needs a last-success
//     timestamp, staleness needs a duration.
//
// # What this file adds
//
// The same shape threatfeed_health.go, socks5_health.go and storage_health.go
// use, and deliberately no new operator vocabulary beyond one event name:
//
//   - /metrics — culvert_syslog_{up,delivered_total,drops_total,panics_total,
//     last_success_timestamp_seconds,stale_seconds,degraded,queue_depth},
//     emitted ONLY when a collector is configured.
//   - /healthz — `syslogDrops`, added only when non-zero, never failing the
//     probe (the addRequestLogHealth precedent exactly).
//   - /api/diagnostics — the existing `syslog_feed` row, extended to consult
//     live delivery instead of only init-time state.
//   - alerts — `syslog_feed_down`, fire-once per episode, recovered on
//     OBSERVED evidence (a delivered line), never on elapsed time.
//   - the process log — onset immediately, then rate-limited, then one recovery
//     line naming the suppressed count.
//
// # Deliberate decisions
//
// **Degradation is a DURATION, not a count.** A single dropped line is a
// transient: the reconnect state machine absorbs one, and a gateway under load
// can overflow the 2048-slot queue during a collector GC pause without anything
// being wrong. Paging on `drops > 0` would page on every such blip. The
// predicate is "no line has been DELIVERED for syslogDegradedAfter while lines
// were being dropped" — the CHAOS-54 rule (a duration, not a count) applied to
// a loss counter rather than an accept-error counter.
//
// **The predicate cannot fire on an idle node.** It requires drops to have
// occurred; a gateway with no traffic produces no lines, drops nothing, and is
// reported healthy, which is correct — there is no evidence either way and
// inventing a fault from silence is how a health plane loses its audience.
//
// **Recovery is on OBSERVED evidence only.** Elapsed time never clears the
// episode: a feed that stopped dropping because nothing is being logged looks
// identical to a feed that started delivering again. This is the discipline
// ca_health.go and storage_health.go both record by name. The consequence,
// stated plainly because it is the real cost: a node whose collector was fixed
// while the node was idle stays reported as degraded until it delivers one
// line. `POST /api/syslog/test` is the operator's way to produce that evidence
// on demand, and the row's OperatorAction says so.
//
// **No /readyz row and no /healthz failure.** A node whose SIEM feed is down is
// proxying perfectly: policy, category, DPI, AV, CDR and the LOCAL audit JSONL
// are all untouched. Failing readiness would eject a healthy gateway from the
// load balancer over its logging plane — converting a compliance gap into a
// traffic outage, which is the trade §19 refused for the category store, §25
// for the admin UI listener, and §27 for the threat feed. Same answer here.
//
// **UDP claims less than TCP and says so.** `udp://` is the DEFAULT when the
// operator omits a scheme. A connected UDP socket's write almost always
// succeeds regardless of whether anything is listening (an ICMP port-unreachable
// surfaces, at best, on a LATER write), so on UDP `Delivered` means "this
// kernel accepted the datagram", not "the SIEM received it". The plane
// therefore cannot detect a dark UDP collector, and every surface that reports
// a UDP feed as delivering is making that weaker claim. This is a property of
// the protocol, not a defect to fix here; it is recorded so nobody reads a
// green `culvert_syslog_up` on UDP as proof the SIEM has the events. Operators
// who need delivery evidence must use `tcp://`.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

const (
	// syslogDegradedAfter is how long the feed must go without a DELIVERED
	// line, while lines are being dropped, before it counts as down.
	//
	// Five minutes, chosen against the engine's own reconnect state machine:
	// deliverLine retries at most every 5 s, so by the time this fires the
	// writer has failed roughly sixty bounded reconnect attempts. That is no
	// longer a blip, and it is short enough that an operator hears about a SIEM
	// outage inside one monitoring interval rather than at the next audit.
	syslogDegradedAfter = 5 * time.Minute

	// syslogLogInterval rate-limits the drop log line: the onset immediately,
	// then at most one line per interval, then one recovery line naming the
	// suppressed count.
	//
	// This is not cosmetic. The drop observer runs once per LOST LINE on the
	// drain goroutine, and during a collector outage that is the full
	// request-log rate — an unrated line would push the process log through
	// internal/logsink at exactly the rate the SIEM feed is failing, which is
	// the CHAOS-54 accept-loop defect (a mitigation that is itself a
	// write-amplification fault) rebuilt one subsystem over.
	syslogLogInterval = 5 * time.Minute
)

// syslogHealthRecord is the process-wide record of the SIEM feed's delivery
// health.
//
// It holds only what the engine cannot: the install-time reference (so a feed
// that has NEVER delivered has an age to measure), the fire-once alert latch,
// and the log rate gate. Counters, the last-success timestamp and the bounded
// failure reason are read live from the Writer's own Stats snapshot, so there
// is exactly one source of truth and no chance of the two drifting.
type syslogHealthRecord struct {
	mu sync.Mutex

	// configured is false until a Writer is installed. Every surface reports
	// the feature as absent then, rather than exporting a zero that is
	// indistinguishable from a broken feed — the CHAOS-54 rule.
	configured bool

	// installedAt anchors the never-delivered age measurement.
	installedAt time.Time

	// target is the operator-facing collector address of the INSTALLED
	// Writer, kept to name the transport in the UDP caveat and to compare
	// against the operator's intent. Never reaches an alert Detail.
	target string

	// intendedTarget is the collector the operator has ASKED for, recorded
	// whether or not a Writer could be installed for it (CHAOS-72 P1-F).
	//
	// Every surface in this file used to gate on `configured`, which is set
	// only once a Writer exists — so a node whose collector was unreachable at
	// boot exported NO culvert_syslog_* series at all. The documented paging
	// rule is `culvert_syslog_up == 0`, and an absent series cannot satisfy
	// it: the one node whose SIEM feed never came up was also the one node
	// monitoring could not see, while a node that connected and then died was
	// fully visible. That is the emission rule of this file (never export a
	// zero for a feature nobody asked for) applied to the wrong question —
	// "is there a Writer" instead of "did an operator ask for one".
	//
	// It duplicates the package-level syslogConfiguredAddr, deliberately: that
	// variable is a plain string read by checkSyslogFeed from handler
	// goroutines and written by the admin plane, whereas this record is read
	// from the DRAIN goroutine (syslogFeedState via noteSyslogDelivery) and so
	// must be mutex-guarded. Both are set at the same four sites. Repointing
	// checkSyslogFeed's init-time branches at this record — which would remove
	// the duplication AND that variable's own unsynchronised read/write pair —
	// is recorded as a follow-up rather than folded in here.
	intendedTarget string
	// intentAt anchors the age of an UNMET intent, which has no install and no
	// delivery to measure from.
	intentAt time.Time

	// retiredDelivered/retiredDrops/retiredPanics carry the totals of every
	// Writer this process has displaced, so the exported counters are
	// PROCESS-lifetime rather than per-Writer (Codex P2, PR #1494).
	//
	// InitSyslog installs a brand-new Writer on a runtime re-point and its
	// counters start at zero — so `culvert_syslog_drops_total` DECREASED
	// without a process restart, which is the one thing a Prometheus counter
	// may not do (`rate()` reads a decrease as a counter reset and discards
	// the interval). It also erased the loss history from `/healthz` and
	// turned the `syslog_feed` row's "N dropped since startup" back to clean —
	// at exactly the moment an operator re-points the collector to REMEDIATE
	// an outage, i.e. the evidence vanishes when it is most wanted. This
	// change's own P1-F comment argued that counters must not go backwards,
	// and the re-point path was doing precisely that one function away.
	//
	// Labelling the series by target was the alternative and is rejected: the
	// label value would be an operator-supplied address, which is the
	// unbounded-label-set defect this sweep records elsewhere (WK-12/RS-5).
	//
	// Residual, documented rather than hidden: a displaced Writer is closed
	// ASYNCHRONOUSLY, so anything it records after this snapshot (its final
	// flush) is not carried. That can only UNDER-count at a generation
	// boundary; it can never make a counter decrease, which is the property
	// that matters.
	retiredDelivered uint64
	retiredDrops     uint64
	retiredPanics    uint64
	// writer is the Writer this record describes. Publication of the active
	// writer and installation of this record are one serialized transition
	// (syslogPublishMu), so writer == activeSyslog() whenever neither is
	// mid-update.
	writer *syslogWriter

	alerted    bool
	logAt      time.Time
	suppressed int64
}

var syslogHealth syslogHealthRecord

// syslogHealthNow is the clock seam. Tests drive degradation deterministically
// instead of sleeping past a five-minute threshold.
//
// Held atomically rather than as a plain var for the same reason as the
// engine's: syslogFeedState is reached from the DRAIN GOROUTINE (via
// noteSyslogDelivery) as well as from HTTP handler goroutines, so a test
// replacing a bare function value races the delivery path — which the
// concurrent-repoint gate catches under -race. Production never writes it and
// pays one atomic load.
var syslogNowFn atomic.Pointer[func() time.Time]

func syslogHealthNow() time.Time {
	if p := syslogNowFn.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
}

// setSyslogHealthNowForTest replaces the clock seam. Test-only.
func setSyslogHealthNowForTest(fn func() time.Time) {
	if fn == nil {
		syslogNowFn.Store(nil)
		return
	}
	syslogNowFn.Store(&fn)
}

// fireSyslogFeedDownAlert delivers the `syslog_feed_down` alert.
//
// Package-level seam so tests observe transitions synchronously rather than
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches). HasSubscriber-gated for the reason documented on
// fireStorageWriteAlert: with no webhook configured — the default posture, and
// the state of every test binary — this must not spawn a goroutine at all.
//
// The Detail carries the engine's BOUNDED reason class, never the collector
// address or a transport error: Dispatch dedups on event+Detail, and a dial
// error embeds the ephemeral local port, so a per-failure-unique Detail would
// defeat the dedup window by construction and evict real threat alerts from the
// 500-entry retry queue (WK-12/RS-5).
var fireSyslogFeedDownAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("syslog_feed_down") {
		return
	}
	go fireAlert("syslog_feed_down", AlertPayload{
		Detail: detail,
		Source: "syslog",
	})
}

// noteSyslogWriterInstalled records a freshly installed Writer and arms the
// delivery observer on it. Called from InitSyslog, so it covers the startup
// path, the persisted-settings path and the live admin re-point identically.
//
// The episode state is reset: a new collector is a new question, and carrying
// the previous target's alert latch forward would suppress the first page for
// the new one.
func noteSyslogWriterInstalled(sw *syslogWriter, target string) {
	if sw == nil {
		return
	}
	syslogHealth.mu.Lock()
	if syslogHealth.writer != sw {
		retireSyslogWriterLocked(syslogHealth.writer)
	}
	syslogHealth.configured = true
	syslogHealth.installedAt = syslogHealthNow()
	syslogHealth.target = target
	syslogHealth.writer = sw
	// An installed Writer IS a satisfied intent, whatever was recorded before.
	// Without this the admin re-point path — which never calls
	// noteSyslogIntent, because it refuses a failed dial with a 400 — would
	// leave the PREVIOUS target recorded as the intent and report the new,
	// working collector as unmet.
	if syslogHealth.intendedTarget != target {
		syslogHealth.intendedTarget = target
		syslogHealth.intentAt = syslogHealth.installedAt
	}
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()
	// A Writer exists again: events are no longer skipped for want of one.
	syslogIntentArmedWithoutWriter.Store(false)

	sw.SetDeliveryObserver(noteSyslogDelivery)
}

// retireSyslogWriterLocked folds a Writer's final counters into the
// process-lifetime totals. Caller holds syslogHealth.mu.
//
// Stats() is a lock-free read of atomics, so calling it under this mutex adds
// no lock-order hazard: it never touches the Writer's own locks.
func retireSyslogWriterLocked(old *syslogWriter) {
	if old == nil {
		return
	}
	st := old.Stats()
	syslogHealth.retiredDelivered += st.Delivered
	syslogHealth.retiredDrops += st.Drops
	syslogHealth.retiredPanics += st.Panics
}

// syslogSkippedNoWriter counts events that reached the audit/request fan-out
// while an operator-configured collector had NO Writer at all — the boot dial
// failed, or forwarding was armed and never came up.
//
// Without it the compliance-loss series this file exists to publish reads ZERO
// throughout the worst outage it can report. P1-F made that state visible
// (`culvert_syslog_up 0`, a degraded row), but every event lost to it was
// skipped at `if sw := activeSyslog(); sw != nil` in store.go and charged to
// nothing: `culvert_syslog_drops_total` stayed 0, `/healthz` carried no
// `syslogDrops`, and an operator asking "how much did I lose?" was answered
// "nothing" while the answer was "everything" (Codex P2, PR #1494).
//
// A Writer's own counters cannot cover this: the loss happens because there is
// no Writer. It is therefore folded into the process-lifetime total, which is
// the one series that means "events that did not reach the SIEM".
var syslogSkippedNoWriter atomic.Uint64

// syslogIntentArmedWithoutWriter gates that counting. It is armed ONLY while an
// operator has asked for a collector and none is installed.
//
// The gate is not an optimisation, it is the same emission rule the metrics
// plane applies: a node that was never asked to forward anywhere is not losing
// anything by not forwarding, and counting there would accrue a large,
// permanent, meaningless "loss" on every appliance that does not use the
// feature. It also keeps the request path to one relaxed atomic load on the
// no-collector branch, which is the common case.
var syslogIntentArmedWithoutWriter atomic.Bool

// noteSyslogEventSkipped charges one event that found no Writer to forward it.
// Called from the audit and request fan-outs in store.go; a no-op unless an
// operator-configured collector is currently unmet.
func noteSyslogEventSkipped() {
	if syslogIntentArmedWithoutWriter.Load() {
		syslogSkippedNoWriter.Add(1)
	}
}

// noteSyslogIntent records that an operator has asked for a collector, BEFORE
// the dial that may or may not produce a Writer for it (CHAOS-72 P1-F).
//
// Called from the two startup paths that tolerate a failed connect — the
// YAML/flag slice and the persisted-admin-settings apply. The live admin
// re-point does not need it: it refuses a failed dial with a 400 and leaves
// the previous target in force, so intent there only ever moves on success.
//
// A repeat of the same target does not re-anchor intentAt: re-applying the
// same unreachable collector on the next boot is the same unmet intent, and
// restarting the clock would make an outage look newer than it is.
func noteSyslogIntent(target string) {
	if target == "" {
		return
	}
	syslogHealth.mu.Lock()
	if syslogHealth.intendedTarget != target {
		syslogHealth.intendedTarget = target
		syslogHealth.intentAt = syslogHealthNow()
	}
	unmet := syslogHealth.writer == nil
	syslogHealth.mu.Unlock()
	syslogIntentArmedWithoutWriter.Store(unmet)
}

// noteSyslogForwardingDisabled records that the operator turned forwarding off,
// so every surface reports the feature as ABSENT again rather than exporting
// stale zeros.
//
// Without it, disabling syslog cleared the writer handle but left the plane
// reporting `configured`, so a switched-off feed kept exporting
// `culvert_syslog_up 1` and a clean `syslog_feed` row forever — a green signal
// for a feature that is not running, which is the same class of false
// statement this whole file exists to remove, just in the other direction.
func noteSyslogForwardingDisabled() {
	syslogHealth.mu.Lock()
	retireSyslogWriterLocked(syslogHealth.writer)
	syslogHealth.configured = false
	syslogHealth.installedAt = time.Time{}
	syslogHealth.target = ""
	syslogHealth.intendedTarget = ""
	syslogHealth.intentAt = time.Time{}

	syslogHealth.writer = nil
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()
}

// noteSyslogDelivery is the delivery observer: called once per DROPPED line,
// and once when a delivery ends a failure episode.
//
// It runs on the drain goroutine and must never call back into the Writer.
// It reads Stats (a lock-free atomic snapshot) and nothing else on that
// object, which is explicitly safe from the drain goroutine's own stack.
func noteSyslogDelivery(delivered bool) {
	if delivered {
		noteSyslogDeliveryRecovered()
		return
	}
	evaluateSyslogDegradation()
}

// evaluateSyslogDegradation fires the alert and the rate-limited log at most
// once per episode. Called from the drop observer (immediate on a busy node)
// and from the watchdog (so a node that went quiet mid-outage still pages).
func evaluateSyslogDegradation() {
	commitSyslogDegradation(syslogFeedState())
}

// commitSyslogDegradation is the commit half, split out so the stale-snapshot
// interleaving can be driven deterministically instead of raced: the window it
// closes is real but cannot be scheduled from a test through the public entry
// point.
func commitSyslogDegradation(snap syslogFeedSnapshot) {
	if !snap.Degraded {
		return
	}

	syslogHealth.mu.Lock()
	// The record may have been REPLACED since this snapshot was taken (an
	// admin re-point runs noteSyslogWriterInstalled, which resets the latch
	// for the new writer). Committing here would page about the old target
	// and, worse, leave the NEW record latched — silencing the replacement's
	// first real outage. The replacement's own evaluation reports it.
	if syslogHealth.writer != snap.writer {
		syslogHealth.mu.Unlock()
		return
	}
	now := syslogHealthNow()
	shouldLog := syslogHealth.logAt.IsZero() || now.Sub(syslogHealth.logAt) >= syslogLogInterval
	if shouldLog {
		syslogHealth.logAt = now
	} else {
		syslogHealth.suppressed++
	}
	alertNow := !syslogHealth.alerted
	syslogHealth.alerted = true
	syslogHealth.mu.Unlock()

	// An UNMET intent gets its own sentence. The general one dates the outage
	// from the last delivery and names a drop count; with no Writer there has
	// never been a delivery and there are no drops to name, so it would read
	// "delivered nothing for 5m (0 events dropped, reason: unknown)" and send
	// an operator looking for a collector that is discarding events, when the
	// remedy is that no connection was ever made. The Detail stays BOUNDED —
	// two fixed sentences, an age and a count — so Dispatch's event+Detail
	// dedup still collapses repeats.
	logLine := fmt.Sprintf("WARN syslog: SIEM feed not delivering — no line has reached the collector for %s (%d lines dropped, last failure %q); audit and request events are NOT reaching the SIEM",
		snap.Age.Round(time.Second), snap.Drops, sanitizeLog(snap.Reason))
	detail := fmt.Sprintf(
		"the remote syslog/SIEM feed has delivered nothing for %s (%d events dropped, reason: %s); audit and request events are not reaching the collector while the node keeps proxying normally",
		snap.Age.Round(time.Second), snap.Drops, reasonOrUnknown(snap.Reason))
	if snap.IntentUnmet {
		logLine = fmt.Sprintf("WARN syslog: SIEM forwarding is configured but NOTHING is serving it — the collector could not be connected %s ago and nothing retries; audit and request events are NOT reaching the SIEM",
			snap.Age.Round(time.Second))
		detail = fmt.Sprintf(
			"remote syslog/SIEM forwarding is configured but no connection was ever established (%s ago) and nothing retries it; audit and request events are not reaching the collector while the node keeps proxying normally",
			snap.Age.Round(time.Second))
	}

	if shouldLog && logger != nil {
		logger.Print(logLine)
	}
	if alertNow {
		fireSyslogFeedDownAlert(detail)
	}
}

// noteSyslogDeliveryRecovered clears the episode on OBSERVED evidence — one
// line that actually reached the collector.
//
// Elapsed time never clears it, for the reason recorded in this file's header
// and by ca_health.go before it.
func noteSyslogDeliveryRecovered() {
	syslogHealth.mu.Lock()
	wasAlerted := syslogHealth.alerted
	suppressed := syslogHealth.suppressed
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()

	if wasAlerted && logger != nil {
		logger.Printf("syslog: SIEM feed delivering again (%d suppressed drop log lines during the episode); events dropped while it was down are NOT replayed",
			suppressed)
	}
}

// syslogWatchdogInterval is how often the degradation transition is
// re-evaluated independently of traffic.
//
// It exists because THE OBSERVER IS DRIVEN BY DROPS, and drops are driven by
// traffic, which stops. A collector that dies, takes a couple of minutes of
// losses and then goes quiet (overnight, or a drained node) crosses the
// five-minute threshold with nothing left to call the evaluator: the metrics
// and the diagnostics row compute the truth on READ, but the `syslog_feed_down`
// alert and the warning log — the surfaces an operator is actually paged by —
// would never fire (Codex P1, PR #1494).
//
// This is the same answer CHAOS-23 reached for the release catalog: when the
// normal driver is not running, a standalone detection-only watchdog ticks at
// the same cadence so the state stays live. Thirty seconds is a tenth of the
// degradation window, so the alert lands within 10% of the threshold; the tick
// itself is one snapshot of atomics and a comparison.
const syslogWatchdogInterval = 30 * time.Second

// startSyslogHealthWatchdog re-evaluates the degradation transition on a timer.
// Started from the background-services slice, parented to the lifecycle ctx.
//
// Detection only: it fires the alert and the rate-limited log the drop observer
// would have fired, and touches nothing else. It no-ops entirely when no
// collector is configured, so a node that forwards nowhere pays one comparison
// per tick.
func startSyslogHealthWatchdog(ctx context.Context) {
	t := time.NewTicker(syslogWatchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			evaluateSyslogDegradation()
		}
	}
}

// syslogFeedSnapshot is the derived view every surface reads.
type syslogFeedSnapshot struct {
	// Configured is true once a Writer has been installed. Distinct from
	// Intended, which is true from the moment an operator asks for a
	// collector — including when the dial that would have produced the Writer
	// failed.
	Configured bool
	// Intended is true when an operator has configured a collector, whether or
	// not a Writer exists to serve it. It is what every EXPORT gates on: the
	// question monitoring asks is "was this feature asked for", not "did it
	// come up".
	Intended bool
	// IntentUnmet is true when a collector is configured and nothing is
	// serving it — either no Writer at all (the boot dial failed), or a Writer
	// still pointing at a PREVIOUS target because a later re-point failed.
	// Nothing retries either case, so it is terminal until an operator acts:
	// it is reported as degraded immediately rather than after the window,
	// which is also what the `syslog_feed` contract row has always done for
	// the same condition.
	IntentUnmet bool
	// NeverDelivered is true when this Writer has never got a line out.
	NeverDelivered bool
	// Degraded is the paging predicate: lines are being lost AND nothing has
	// been delivered for syslogDegradedAfter.
	Degraded bool
	// Age is the time since the last delivered line, or since the Writer was
	// installed when nothing has ever been delivered.
	Age         time.Duration
	LastSuccess time.Time
	// Delivered/Drops/Panics are PROCESS-lifetime totals: the live Writer's
	// counters plus every displaced Writer's final ones. They must be
	// monotonic across a runtime re-point, which installs a fresh Writer whose
	// own counters start at zero — see retiredDrops on the health record.
	// Everything else in this snapshot describes the CURRENT Writer only
	// (NeverDelivered, ConsecutiveFailures, LastSuccess, FailingFor), because
	// those are statements about the episode in progress, not about history.
	Delivered uint64
	Drops     uint64
	Panics    uint64
	// WriterDrops is the CURRENT Writer's own drop count. Any sentence that
	// makes a claim about THIS target uses it; Drops (process-lifetime) is for
	// "in total since startup". Blaming a freshly re-pointed collector for the
	// losses of the one it replaced is the same false statement this file
	// exists to remove, arriving through the counter that fixed a different
	// one.
	WriterDrops uint64
	// ConsecutiveFailures is the count of losses since the last delivered
	// event — zero means the last thing this writer did was succeed.
	ConsecutiveFailures uint64
	Reason              string
	QueueDepth          int
	QueueCap            int
	// FailingFor is how long the CURRENT unresolved failure episode has
	// lasted (zero when ConsecutiveFailures is 0).
	FailingFor time.Duration
	// UDP records that this feed cannot prove delivery; see the header.
	UDP bool

	// writer is the Writer this snapshot describes. A caller that SNAPSHOTS
	// and then COMMITS a decision under the lock must check it still holds:
	// an admin re-point between the two installs a new record, and a stale
	// callback committing into it fires a page describing the OLD target AND
	// sets the new record's fire-once latch — which then suppresses the
	// replacement's first real outage, because ordinary deliveries do not
	// invoke the observer and nothing else clears it (Codex P1, PR #1494).
	writer *syslogWriter
}

// syslogFeedState derives the current posture from the Writer's own stats plus
// this file's install-time anchor.
//
// Evaluated on every read, never latched (the ca_health.go Usable() discipline)
// — so recovery needs no clearing path and a wedged feed keeps telling the
// truth without anything having to run.
func syslogFeedState() syslogFeedSnapshot {
	syslogHealth.mu.Lock()
	configured := syslogHealth.configured
	installedAt := syslogHealth.installedAt
	target := syslogHealth.target
	described := syslogHealth.writer
	intendedTarget := syslogHealth.intendedTarget
	intentAt := syslogHealth.intentAt
	retiredDelivered := syslogHealth.retiredDelivered
	retiredDrops := syslogHealth.retiredDrops
	retiredPanics := syslogHealth.retiredPanics
	syslogHealth.mu.Unlock()

	// The caveat describes the transport the operator ASKED for when nothing
	// is installed — there is no Writer whose scheme could be reported.
	caveatTarget := target
	if caveatTarget == "" {
		caveatTarget = intendedTarget
	}
	now := syslogHealthNow()
	snap := syslogFeedSnapshot{
		writer:     described,
		Configured: configured,
		Intended:   intendedTarget != "",
		UDP:        !strings.HasPrefix(strings.ToLower(caveatTarget), "tcp://"),
	}
	snap.IntentUnmet = snap.Intended && (described == nil || target != intendedTarget)
	// Retired totals are carried even when no Writer is live, so a disabled or
	// failed-to-reconnect feed still reports the events it has already lost.
	snap.Delivered = retiredDelivered
	// Events that found no Writer at all belong to the process-lifetime total:
	// they did not reach the SIEM, and no Writer's counters can hold them.
	snap.Drops = retiredDrops + syslogSkippedNoWriter.Load()
	snap.Panics = retiredPanics
	sw := activeSyslog()
	if !configured || sw == nil {
		return finishUnmetSyslogIntent(snap, now, intentAt)
	}
	st := sw.Stats()
	snap.Delivered += st.Delivered
	snap.Drops += st.Drops
	snap.Panics += st.Panics
	snap.WriterDrops = st.Drops
	snap.ConsecutiveFailures = st.ConsecutiveFailures
	snap.Reason = st.LastFailureReason
	snap.QueueDepth = st.QueueDepth
	snap.QueueCap = st.QueueCap
	snap.LastSuccess = st.LastSuccess

	ref := st.LastSuccess
	if ref.IsZero() {
		snap.NeverDelivered = true
		ref = installedAt
	}
	if !ref.IsZero() {
		snap.Age = now.Sub(ref)
	}
	// A negative age means the clock moved backwards under us (NTP step, VM
	// restore). Report fresh rather than degraded: the line genuinely was
	// delivered, and paging on a clock correction is noise. Same call
	// threatFeedState makes, for the same reason.
	if snap.Age < 0 {
		snap.Age = 0
	}
	// Degradation requires BOTH halves: an UNRESOLVED failure, and no delivery
	// for the window.
	//
	// The failure half is ConsecutiveFailures, NOT the cumulative Drops
	// counter. Drops never resets, so keying on it meant that one transient
	// loss — a queue overflow during a collector GC pause, weeks ago — armed
	// the first half permanently; the node then only had to go quiet for five
	// minutes for Age to cross the threshold and every surface to report a
	// perfectly healthy feed as DOWN. A false page on a working SIEM, from a
	// blip that already healed (Codex P1, PR #1494). ConsecutiveFailures is
	// reset by the engine on every delivery, so it means what this predicate
	// needs it to mean: something is failing NOW.
	//
	// The age half still measures from the last DELIVERY, which is what makes
	// the pair unable to fire on an idle node: no traffic means no failures,
	// so the first half is false however old the last delivery is.
	//
	// And the failing episode ITSELF must have lasted the window. Timing only
	// from the last delivery meant a feed that had been healthy but idle for
	// longer than the window paged on the very next transient drop — the
	// episode was seconds old but Age was already past the threshold (Codex
	// P1, PR #1494). FailingSince is the first loss after the last delivery.
	if snap.ConsecutiveFailures > 0 && !st.FailingSince.IsZero() {
		snap.FailingFor = now.Sub(st.FailingSince)
		if snap.FailingFor < 0 {
			snap.FailingFor = 0
		}
	}
	snap.Degraded = snap.ConsecutiveFailures > 0 &&
		snap.Age >= syslogDegradedAfter &&
		snap.FailingFor >= syslogDegradedAfter
	return finishUnmetSyslogIntent(snap, now, intentAt)
}

// finishUnmetSyslogIntent overlays the unmet-intent verdict onto a snapshot.
//
// It runs on BOTH exits of syslogFeedState because the condition has two
// shapes: no Writer at all (the boot dial failed) and a Writer serving a
// target the operator has since moved away from (a later re-point failed).
// The second one still has live counters, and they are left untouched — the
// drops a displaced Writer recorded are real events that never reached any
// SIEM, and zeroing them would make culvert_syslog_drops_total go BACKWARDS,
// which breaks rate() on the one series that measures compliance loss.
//
// Only the verdict and the age are overlaid: the feed is DOWN, and it has been
// down for as long as the intent has gone unserved (the longer of that and any
// staleness the displaced Writer already reported, so an observed outage is
// never shortened by a fresher intent stamp).
func finishUnmetSyslogIntent(snap syslogFeedSnapshot, now time.Time, intentAt time.Time) syslogFeedSnapshot {
	if !snap.IntentUnmet {
		return snap
	}
	snap.Degraded = true
	snap.NeverDelivered = snap.LastSuccess.IsZero()
	if !intentAt.IsZero() {
		if age := now.Sub(intentAt); age > snap.Age {
			snap.Age = age
		}
	}
	if snap.Age < 0 {
		snap.Age = 0
	}
	return snap
}

// syslogUDPCaveat is the sentence appended wherever a UDP feed is reported as
// healthy. One string, so the two surfaces cannot drift.
const syslogUDPCaveat = " (UDP: delivery to the collector cannot be confirmed — only that this host sent the datagrams; use tcp:// for delivery evidence)"

// checkSyslogFeedDelivery is the delivery half of the `syslog_feed` operator
// contract row, consulted by checkSyslogFeed after its init-time branches.
//
// Severity policy:
//   - degraded → FAIL. Unlike a stale threat feed (a WARN, because the gateway
//     is still enforcing last-known-good intelligence), a dark SIEM feed means
//     the security record is being destroyed as it is produced — there is no
//     degraded-but-useful state to fall back on, and the events lost are gone
//     for good.
//   - dropping but recently delivered → WARN, naming the count. A transient
//     collector stall is worth seeing without being worth paging.
//   - clean → ok, carrying the cumulative drop count so a HISTORY of transient
//     loss stays visible after recovery.
func checkSyslogFeedDelivery() (OperatorContractCheck, bool) {
	snap := syslogFeedState()
	if !snap.Configured {
		return OperatorContractCheck{}, false
	}
	if snap.Degraded {
		what := fmt.Sprintf("no event has reached the collector for %s", snap.Age.Round(time.Second))
		if snap.NeverDelivered {
			what = fmt.Sprintf("no event has EVER reached the collector since this target was configured %s ago", snap.Age.Round(time.Second))
		}
		dropped := snap.WriterDrops
		if dropped == 0 {
			dropped = snap.Drops
		}
		return OperatorContractCheck{
			Code:   "syslog_feed",
			Status: diagFail,
			Message: fmt.Sprintf("remote syslog/SIEM forwarding is DOWN: %s and %d event(s) have been dropped (last failure: %s). Audit and request events are not reaching the SIEM; the node keeps proxying normally and the local audit log is unaffected",
				what, dropped, reasonOrUnknown(snap.Reason)),
			OperatorAction: "Restore the collector (host/port, listener, network path, and for tcp:// the collector's connection limit), then confirm with POST /api/syslog/test — recovery is declared only on an event that actually reaches the collector, so a quiet node stays reported as down until one does. Events dropped while the feed was down are NOT replayed.",
		}, true
	}
	// Drops, but not degraded. Three DIFFERENT states reach here and only one
	// of them is "delivering with some history of loss" — saying that sentence
	// for the other two is the false statement this whole sweep exists to
	// remove, pointing at its own row (Codex P2, PR #1494).
	//
	// The second and third cases became reachable when the degradation window
	// moved from time-since-delivery to the failure EPISODE (P1-D): before
	// that, a feed failing right now on a node quiet for five minutes was
	// already FAIL, so this branch only ever saw healed history. Fixing the
	// window widened what this branch has to describe — a boundary moved in
	// one place has to be re-read everywhere downstream of it.
	if snap.Drops > 0 {
		switch {
		case snap.NeverDelivered && snap.WriterDrops > 0:
			// No delivery has EVER happened, so there is no "last event" to
			// date and no delivery to claim. Distinct from the degraded branch
			// only by how long it has been failing.
			return OperatorContractCheck{
				Code:   "syslog_feed",
				Status: diagWarn,
				Message: fmt.Sprintf("remote syslog/SIEM forwarding has NEVER delivered an event since this target was configured %s ago, and %d event(s) have already been dropped (last failure: %s)",
					snap.Age.Round(time.Second), snap.WriterDrops, reasonOrUnknown(snap.Reason)),
				OperatorAction: "Treat this as a misconfigured or unreachable target rather than a transient stall: check the host/port, that the collector is listening, the network path, and for tcp:// the collector's connection limit. Confirm with POST /api/syslog/test. Nothing has reached the SIEM yet, and the dropped events are not replayed.",
			}, true

		case snap.NeverDelivered:
			// Nothing has gone wrong with THIS target yet — it simply has not
			// carried an event. The drops on the books belong to a Writer it
			// replaced, and the counters are process-lifetime by design (a
			// re-point must not reset the loss history), so the row reports
			// the history as history and does not blame the new collector for
			// it.
			return OperatorContractCheck{
				Code:   "syslog_feed",
				Status: diagWarn,
				Message: fmt.Sprintf("remote syslog/SIEM forwarding is connected; no event has been forwarded to this target yet. %d event(s) were lost to an earlier target in this process and are not replayed",
					snap.Drops),
				OperatorAction: "No action is needed for the current target — the loss predates it. Confirm the new collector with POST /api/syslog/test; the earlier events are gone and are not re-sent.",
			}, true

		case snap.ConsecutiveFailures > 0:
			// Failing RIGHT NOW, just not for long enough to page. Reporting
			// "is delivering" here would describe the last success while the
			// current events are being destroyed.
			return OperatorContractCheck{
				Code:   "syslog_feed",
				Status: diagWarn,
				Message: fmt.Sprintf("remote syslog/SIEM forwarding is FAILING NOW: %d event(s) lost since the last delivery %s ago (failing for %s, %d dropped in total, last failure: %s). This is below the %s threshold that reports the feed down",
					snap.ConsecutiveFailures, snap.Age.Round(time.Second), snap.FailingFor.Round(time.Second),
					snap.Drops, reasonOrUnknown(snap.Reason), syslogDegradedAfter),
				OperatorAction: "The writer reconnects on its own and a single delivery ends the episode, so a short stall needs no action. If this persists it becomes a DOWN verdict; check collector ingest capacity, the listener and the network path now rather than after the threshold. Events lost during the stall are not replayed.",
			}, true

		default:
			// Delivering, with a healed history of loss — the only state the
			// original sentence was ever true for.
			return OperatorContractCheck{
				Code:   "syslog_feed",
				Status: diagWarn,
				Message: fmt.Sprintf("remote syslog/SIEM forwarding is delivering (last event %s ago, %d delivered) but %d event(s) have been dropped since startup (last failure: %s) — those events are not in the SIEM and are not replayed",
					snap.Age.Round(time.Second), snap.Delivered, snap.Drops, reasonOrUnknown(snap.Reason)),
				OperatorAction: "Transient collector stalls are absorbed by the writer's reconnect; a rising drop count means the collector is slower than this node's event rate. Check collector ingest capacity and the network path.",
			}, true
		}
	}
	msg := fmt.Sprintf("remote syslog/SIEM forwarding is active (%d events delivered, last %s ago)", snap.Delivered, snap.Age.Round(time.Second))
	if snap.NeverDelivered {
		msg = "remote syslog/SIEM forwarding is connected; no event has been forwarded yet"
	}
	if snap.UDP {
		msg += syslogUDPCaveat
	}
	return OperatorContractCheck{
		Code:    "syslog_feed",
		Status:  diagOK,
		Message: msg,
	}, true
}

// syslogWritePrometheus appends the culvert_syslog_* delivery series.
//
// Every series here is emitted ONLY when a collector is configured. A
// `culvert_syslog_up 0` on a node that forwards nowhere is indistinguishable
// from a node whose SIEM feed is dark, and the documented paging rule is
// `== 0` — so an unconditional gauge would page every deployment that does not
// use the feature. Same rule as the SOCKS5, cluster-CA, DNS and threat-feed
// gauges.
func syslogWritePrometheus(w *strings.Builder) {
	snap := syslogFeedState()
	// EITHER half admits the series. Configured alone was the gate, and it is
	// set only once a Writer exists — so the node whose collector was
	// unreachable at boot exported nothing, and `culvert_syslog_up == 0` could
	// not fire for precisely the feed that never came up (CHAOS-72 P1-F). The
	// emission rule is about whether the feature was ASKED for; an operator
	// who configured a collector has asked, and gets a truthful 0.
	if !snap.Configured && !snap.Intended {
		return
	}

	w.WriteString("\n# HELP culvert_syslog_up 1 when the remote syslog/SIEM feed is delivering, 0 when it has lost events and delivered nothing for the degradation window\n")
	w.WriteString("# TYPE culvert_syslog_up gauge\n")
	fmt.Fprintf(w, "culvert_syslog_up %d\n", boolGauge(!snap.Degraded))

	w.WriteString("\n# HELP culvert_syslog_degraded 1 when the remote syslog/SIEM feed has been losing events with no successful delivery for the degradation window\n")
	w.WriteString("# TYPE culvert_syslog_degraded gauge\n")
	fmt.Fprintf(w, "culvert_syslog_degraded %d\n", boolGauge(snap.Degraded))

	w.WriteString("\n# HELP culvert_syslog_delivered_total Events written to the remote syslog/SIEM collector socket\n")
	w.WriteString("# TYPE culvert_syslog_delivered_total counter\n")
	fmt.Fprintf(w, "culvert_syslog_delivered_total %d\n", snap.Delivered)

	// The compliance-critical series: every increment is one audit or request
	// event that exists nowhere in the SIEM and is never replayed.
	w.WriteString("\n# HELP culvert_syslog_drops_total Events lost before reaching the remote syslog/SIEM collector (collector down, queue overflow, writer closed, or no connection ever established)\n")
	w.WriteString("# TYPE culvert_syslog_drops_total counter\n")
	fmt.Fprintf(w, "culvert_syslog_drops_total %d\n", snap.Drops)

	w.WriteString("\n# HELP culvert_syslog_panics_total Events lost to a recovered panic in the syslog delivery goroutine\n")
	w.WriteString("# TYPE culvert_syslog_panics_total counter\n")
	fmt.Fprintf(w, "culvert_syslog_panics_total %d\n", snap.Panics)

	w.WriteString("\n# HELP culvert_syslog_last_success_timestamp_seconds Unix time of the last event delivered to the collector (0 = never)\n")
	w.WriteString("# TYPE culvert_syslog_last_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_syslog_last_success_timestamp_seconds %d\n", unixOrZero(snap.LastSuccess))

	// Exported alongside the timestamp because the never-delivered case has no
	// timestamp to subtract from, and that is the case most worth alerting on.
	w.WriteString("\n# HELP culvert_syslog_stale_seconds Seconds since the last event was delivered to the collector (since the target was configured when none ever has)\n")
	w.WriteString("# TYPE culvert_syslog_stale_seconds gauge\n")
	fmt.Fprintf(w, "culvert_syslog_stale_seconds %d\n", int64(snap.Age.Seconds()))

	w.WriteString("\n# HELP culvert_syslog_queue_depth Events queued for delivery to the collector\n")
	w.WriteString("# TYPE culvert_syslog_queue_depth gauge\n")
	fmt.Fprintf(w, "culvert_syslog_queue_depth %d\n", snap.QueueDepth)
}

// syslogDropCount is the /healthz accessor. Zero when no collector is
// configured, so the field stays absent on a node that forwards nowhere.
func syslogDropCount() uint64 {
	snap := syslogFeedState()
	if !snap.Configured {
		return 0
	}
	return snap.Drops
}

// syslogDeliveryProbe sends one line and waits a bounded time for the drain
// goroutine to report an outcome for it. Used by POST /api/syslog/test.
//
// The endpoint previously called Write and answered {"ok": true} — which, once
// delivery became asynchronous, confirmed only that a channel send succeeded.
// It returned ok for a collector that had been dead for a week, and
// checkSyslogFeed's own OperatorAction pointed operators at it to "confirm
// connectivity". A probe that cannot fail is worse than no probe.
//
// Bounded at syslogProbeWait: the write path's own worst case is a 5 s write
// deadline plus a 5 s dial plus a 5 s write deadline, and an admin request must
// not be held for that. A probe that times out reports `unknown` rather than a
// failure — the line may yet be delivered, and claiming a failure we did not
// observe is the mistake this whole file exists to stop.
const syslogProbeWait = 3 * time.Second

func syslogDeliveryProbe(sw *syslogWriter) (outcome string, detail string) {
	if sw == nil {
		return "unconfigured", "no collector is configured"
	}
	syslogHealth.mu.Lock()
	target := syslogHealth.target
	syslogHealth.mu.Unlock()

	// WriteProbe reports the outcome of THIS message, from the drain
	// goroutine. The first shape of this function compared writer-wide
	// Delivered/Drops counters around the write, which is not the same
	// question: on a gateway with concurrent audit and request traffic another
	// line's delivery lands between the snapshot and the read, so the probe
	// answered "delivered" while its own message was still queued behind a
	// collector about to drop it — and a drop could likewise be blamed on the
	// probe (Codex P1, PR #1494). An endpoint whose whole job is to be
	// believed may not infer its answer.
	ack, queued := sw.WriteProbe("Culvert syslog test message — connectivity probe")
	if !queued {
		return "dropped", "the test event could not be queued for delivery (" + reasonOrUnknown(sw.Stats().LastFailureReason) + ")"
	}

	// time.After, deliberately NOT the syslogHealthNow seam: this waits on real
	// socket I/O, not on a freshness computation, so it must advance even when
	// a test has frozen the clock to drive degradation — against a frozen seam
	// the wait would never expire and the probe would hang.
	select {
	case delivered := <-ack:
		if !delivered {
			return "dropped", "the test event was lost before reaching the collector (" + reasonOrUnknown(sw.Stats().LastFailureReason) + ")"
		}
		if !strings.HasPrefix(strings.ToLower(target), "tcp://") {
			return "sent", "datagram sent; UDP cannot confirm the collector received it — use tcp:// for delivery evidence"
		}
		return "delivered", "the collector accepted the test event"
	case <-time.After(syslogProbeWait):
		return "unknown", "no delivery outcome within the probe window; the event is still queued"
	}
}

// resetSyslogHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so replacing it wholesale under the lock
// would swap the held mutex for an unlocked zero value.
func resetSyslogHealthForTest() {
	syslogHealth.mu.Lock()
	syslogHealth.retiredDelivered = 0
	syslogHealth.retiredDrops = 0
	syslogHealth.retiredPanics = 0
	syslogHealth.configured = false
	syslogHealth.installedAt = time.Time{}
	syslogHealth.target = ""
	syslogHealth.intendedTarget = ""
	syslogHealth.intentAt = time.Time{}

	syslogHealth.writer = nil
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()
	syslogIntentArmedWithoutWriter.Store(false)
	syslogSkippedNoWriter.Store(0)
	setSyslogHealthNowForTest(nil)
}

// syslogReasonClasses is the closed set the engine can report, mirrored here so
// a surface test can pin that no raw error string reaches an operator surface.
var syslogReasonClasses = []string{
	syslog.ReasonQueueFull,
	syslog.ReasonClosed,
	syslog.ReasonConnectFail,
	syslog.ReasonWriteFail,
	syslog.ReasonBackoff,
	syslog.ReasonPanic,
	syslog.ReasonFlushTimeout,
}
