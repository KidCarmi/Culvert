package main

// syslog_health.go — the SIEM forwarding feed's delivery-health plane.
//
// # Why this file exists
//
// Culvert forwards two records to the customer's SIEM over the syslog feed:
// the ADMIN AUDIT TRAIL (store.go's recordAudit → globalSyslog.WriteAudit) and
// the REQUEST LOG (recordRequest → WriteRequest). For a lot of deployments the
// collector is the only copy anyone ever reads — the node-local JSONL is a 50
// MB rotating file with one archive, and in a cluster the central trail is the
// SIEM's.
//
// Delivery is best-effort by design and stays that way: a wedged collector
// must cost a counter, never proxy latency. That posture was right. What was
// missing is the half that makes it acceptable — the loss was invisible.
//
// Measured against the real binary before this change (see the gates in
// syslog_health_chaos_test.go):
//
//   - A TCP collector that dies AFTER a successful startup connect: 49 of 50
//     audit lines lost, and `checkSyslogFeed` — the operator-contract row whose
//     own doc-comment says it exists to distinguish "configured but silently
//     down" — kept reporting **"remote syslog/SIEM forwarding is active"**. It
//     keys on `globalSyslog == nil`, and the Writer never nils itself: the
//     conn goes nil inside the engine, `globalSyslog` stays non-nil forever, so
//     the row could only ever detect the BOOT failure. The runtime failure —
//     SIEM restart, firewall change, collector redeploy, the common case — was
//     structurally invisible to it.
//
//   - `Drops()` had exactly ONE reader in the tree: the admin-only
//     `GET /api/syslog` JSON blob. No /metrics series, no /healthz field, no
//     alert, and not one log line. Prometheus could not see SIEM loss at all.
//
// That is CWE-778 / A09:2021, and it is the third instance of one pattern in
// this register: internal/audit closed it for the local file (ST-8) and the
// DP→CP push queue closed it for the cluster path (CL-21, CHAOS-61). The sink
// that had none of it was the one that leaves the appliance.
//
// # What this file adds
//
// The same shape threatfeed_health.go, socks5_health.go and admin_ui_health.go
// use, and deliberately no new operator vocabulary beyond one event name:
//
//   - /metrics — culvert_syslog_{up,drops_total{reason},
//     last_delivery_timestamp_seconds,degraded,failing_seconds,
//     delivery_confirmable,queue_capacity}.
//   - /api/diagnostics — the `syslog_feed` row now reports the RUNTIME state.
//   - /healthz — a `syslogFeed` field, added only when degraded.
//   - alerts — `siem_feed_down`, fire-once per episode, recovered on OBSERVED
//     evidence (a delivered line), never on elapsed time.
//
// # Four rules, each load-bearing
//
// **(1) Degradation is a DURATION, and it is keyed on an OBSERVED FAILURE,
// never on silence.** The obvious metric is "time since the last successful
// delivery" and it is wrong: a gateway with no traffic sends no lines, so that
// clock advances with no fault present and every quiet appliance eventually
// pages. The engine arms `FailingSince` on an observed failure and clears it
// on an observed success (internal/syslog/observability.go invariant (2)), so
// an idle feed reports nothing in either direction. This is CHAOS-57's lesson
// — the evidence must match the claim — applied before it could be made again.
//
// **(2) Recovery is declared on OBSERVED evidence only.** One line the
// transport accepted clears the episode. Elapsed time never does: a feed that
// stopped reporting failures because nothing is being sent looks identical to
// a healthy one, which is the mistake ca_health.go and storage_health.go both
// call out by name.
//
// **(3) Every series is emitted ONLY when syslog is configured.** A
// `culvert_syslog_up 0` on the overwhelming majority of deployments — which do
// not forward to a SIEM at all — is indistinguishable from a broken feed, and
// the documented paging rule is `== 0`. Same rule as the SOCKS5, cluster-CA
// and DNS gauges.
//
// **(4) The alert Detail carries a BOUNDED reason class**, never the collector
// address or a raw transport error. `alerts.Store.Dispatch` dedups on
// event+Detail; an error string embeds the ephemeral local port, so a
// per-failure-unique Detail defeats the dedup window by construction and
// evicts real threat alerts from the 500-entry retry queue (the WK-12/RS-5
// defect). The address stays on the role-gated admin API and in the log.
//
// # What it deliberately does NOT add
//
// **No /readyz row, and no /healthz FAILURE.** A node whose SIEM feed is down
// is a fully serving gateway: policy, inspection, scanning and egress are all
// unaffected, and the audit trail is still being written to local disk. Failing
// readiness would eject a healthy gateway from the load balancer over its
// LOGGING pipeline — converting a monitoring outage into a traffic outage,
// which is the exact trade §19 refused for the category store and §25 refused
// for the admin UI listener. The `syslogFeed` field on /healthz is reported,
// never fatal. Pinned as a CONTROL test.
//
// **No fail-closed toggle.** Blocking traffic because a log collector is
// unreachable would convert the SIEM's outage into the customer's outage. The
// gateway's own audit file is unaffected by a SIEM outage, so there is no
// integrity argument for refusing to serve.
//
// # The limit, on UDP — stated rather than hidden
//
// UDP is the DEFAULT transport (InitSyslog picks it when the address carries
// no scheme). A connected UDP socket to a collector that does not exist
// accepts every write; measured on the reference container, `NewWriter`
// SUCCEEDS against a dead UDP collector and 200 audit lines are written into
// the void with `Drops()` still at zero. No signal in this file can see that,
// and none of them claims to: `culvert_syslog_delivery_confirmable` reports 0
// for UDP, the contract row says in words that "active" means the socket is
// open rather than that the collector received anything, and the runbook tells
// an operator who needs delivery assurance to use `tcp://`. That is a property
// of the protocol, not a defect this plane can close.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

const (
	// syslogDegradedAfter is how long a feed must be CONTINUOUSLY failing —
	// measured from the first observed failure, not from the last success —
	// before it is reported as degraded and paged.
	//
	// A duration rather than a drop count, for the reason the SOCKS5 and DNS
	// planes record: a collector restart, a rolling SIEM upgrade or a brief
	// network blip drops lines for a few seconds on a busy gateway and is not
	// worth waking anyone for, while a count-based threshold makes the page
	// depend on this node's traffic rate rather than on the fault.
	syslogDegradedAfter = 60 * time.Second

	// syslogLogInterval rate-limits the degradation log line: the onset
	// immediately, then at most one line per interval, then one recovery line
	// naming the suppressed count.
	//
	// A mitigation for a log-loss defect must not be one itself: on a busy
	// gateway every proxied request produces a line for this feed, so a
	// per-drop log line would write the process log at request rate into a
	// rotating file with one archive — reproducing, in the local log, exactly
	// the destruction-by-volume this sweep exists to make visible. The log
	// carries the SIGNAL; the counter carries the MAGNITUDE.
	syslogLogInterval = 5 * time.Minute
)

// syslogHealthRecord is the process-wide record of the SIEM feed's delivery
// health.
//
// It holds only what the engine cannot: whether the operator configured a feed
// at all, and the edge-triggered alert/log gates. Everything else (last
// delivery, failing-since, per-reason drops) is read live from the Writer's own
// atomics, so there is exactly one source of truth and no chance of the two
// drifting.
type syslogHealthRecord struct {
	mu sync.Mutex

	// configured is false until a syslog target is set. Every surface reports
	// the feature as absent then, rather than exporting a zero that is
	// indistinguishable from a broken feed — the CHAOS-54 rule.
	configured bool

	// alerted latches the down alert for the duration of one episode, so a
	// collector that stays down does not re-page on every transition. Cleared
	// only by an OBSERVED delivery.
	alerted bool

	// logAt / suppressed drive the rate-limited log line.
	logAt      time.Time
	suppressed int64

	// degradeTimer fires once per episode, at the degradation threshold, so the
	// alert does not depend on anyone reading a surface. See
	// armSyslogDegradeCheck.
	degradeTimer *time.Timer
}

var syslogHealth syslogHealthRecord

// syslogHealthClock is the clock seam. Tests drive the degradation threshold
// deterministically instead of sleeping past a 60-second window.
//
// It is an atomic.Pointer rather than a plain `var f = time.Now`, which is the
// shape the other health planes use, because THIS seam is read from a
// BACKGROUND goroutine: noteSyslogDeliveryFailing runs on the engine's drain
// goroutine via the delivery observer, so a test swapping the clock races it.
// `-race` caught exactly that. Production never reassigns it, so the race was
// test-only — but a seam that is read off-goroutine has to be published safely
// or the gate that would catch a real regression gets muted as "the flaky one".
var syslogHealthClock atomic.Pointer[func() time.Time]

// syslogHealthNow reads the clock seam, defaulting to the real clock.
func syslogHealthNow() time.Time {
	if p := syslogHealthClock.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
}

// setSyslogHealthClockForTest installs a deterministic clock; nil restores the
// real one. Test isolation only.
func setSyslogHealthClockForTest(fn func() time.Time) {
	if fn == nil {
		syslogHealthClock.Store(nil)
		return
	}
	syslogHealthClock.Store(&fn)
}

// fireSyslogDownAlert delivers the `siem_feed_down` alert.
//
// Package-level seam so tests observe transitions synchronously rather than
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches).
//
// HasSubscriber-gated for the reason documented on fireStorageWriteAlert: with
// no webhook configured — the default posture, and the state of every test
// binary — this must not spawn a goroutine at all. The gate changes no
// behaviour, since Dispatch filters non-matching webhooks anyway.
//
// A NEW event name is justified here rather than reusing an existing one:
// there is no other event in the tree whose operator action is "your SIEM feed
// is not delivering". The repo's standing caution — a new name is silently
// unsubscribed on every already-configured webhook — is the reason the
// operator-contract row and the metric, which need no subscription, are the
// primary surfaces and the alert is the third. Same precedent as
// `socks5_listener_down` (CHAOS-54) and `admin_ui_unavailable` (CHAOS-57).
var fireSyslogDownAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("siem_feed_down") {
		return
	}
	go fireAlert("siem_feed_down", AlertPayload{
		Detail: detail,
		Source: "syslog",
	})
}

// noteSyslogConfigured records that a syslog target is in effect and installs
// the delivery observer on the live Writer.
//
// Called from every path that installs a Writer — the observability startup
// slice, the persisted admin-settings apply, and the runtime POST /api/syslog
// — so a feed reconfigured at runtime is observed exactly like one configured
// at boot. A reconfigure builds a NEW Writer, so the observer must be
// re-installed on it; the episode gates are reset with it, because the
// previous collector's episode says nothing about the new one.
func noteSyslogConfigured(w *syslogWriter) {
	syslogHealth.mu.Lock()
	syslogHealth.configured = true
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()

	if w != nil {
		w.SetDeliveryObserver(noteSyslogDelivery)
	}
}

// noteSyslogUnconfigured records that syslog forwarding was turned off. Every
// surface goes back to reporting the feature as absent rather than as healthy
// or broken.
func noteSyslogUnconfigured() {
	syslogHealth.mu.Lock()
	syslogHealth.configured = false
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()
}

// noteSyslogDelivery is the delivery observer: one call per TRANSITION between
// delivering and failing, never per line.
//
// It runs on the engine's drain goroutine, so it must never call back into the
// Writer's send path — the same rule audit.SetWriteFailureObserver carries, for
// the same reason (re-entering the sink from its own failure handler recurses
// without bound on a persistently failing one). It logs and evaluates; it does
// not forward anything to syslog.
func noteSyslogDelivery(ev syslog.DeliveryEvent) {
	switch ev.State {
	case syslog.DeliveryFailing:
		noteSyslogDeliveryFailing(ev)
	case syslog.DeliveryRecovered:
		noteSyslogDeliveryRecovered(ev)
	}
}

func noteSyslogDeliveryFailing(ev syslog.DeliveryEvent) {
	syslogHealth.mu.Lock()
	now := syslogHealthNow()
	shouldLog := syslogHealth.logAt.IsZero() || now.Sub(syslogHealth.logAt) >= syslogLogInterval
	if shouldLog {
		syslogHealth.logAt = now
	} else {
		syslogHealth.suppressed++
	}
	syslogHealth.mu.Unlock()

	if shouldLog && logger != nil {
		// The reason is a BOUNDED class, so this line cannot carry
		// attacker-influenced or high-cardinality content. sanitizeLog is
		// applied anyway, per the house rule that every value reaching the
		// process log goes through it.
		logger.Printf("SYSLOG: SIEM forwarding is FAILING (reason=%q, %d lines lost so far) — audit and request records are not reaching the collector; the node-local audit log is unaffected",
			sanitizeLog(string(ev.Reason)), ev.Drops)
	}
	// The episode has opened but is not degraded yet, so there is nothing to
	// alert on now. Schedule the check that decides, so the page does not
	// depend on someone scraping /metrics or opening the admin UI.
	armSyslogDegradeCheck()
}

// noteSyslogDeliveryRecovered clears the episode on OBSERVED evidence — one
// line the transport accepted.
func noteSyslogDeliveryRecovered(ev syslog.DeliveryEvent) {
	stopSyslogDegradeCheck()
	syslogHealth.mu.Lock()
	wasAlerted := syslogHealth.alerted
	suppressed := syslogHealth.suppressed
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()

	if logger != nil && (wasAlerted || ev.FailingFor > 0) {
		logger.Printf("SYSLOG: SIEM forwarding RECOVERED after %s (%d lines lost in total during the episode, %d suppressed log lines) — the lost records are NOT retransmitted; recover them from this node's local audit log if the gap matters",
			ev.FailingFor.Round(time.Second), ev.Drops, suppressed)
	}
}

// syslogScheduleDegradeCheck is the timer seam. Tests substitute it to run the
// scheduled evaluation synchronously instead of waiting out the threshold.
var syslogScheduleDegradeCheck = time.AfterFunc

// armSyslogDegradeCheck schedules ONE evaluation at the degradation threshold,
// so the alert fires without anyone reading a surface.
//
// This exists because the read-driven evaluation alone was not enough, and the
// gap was the same shape as this whole sweep's finding (Codex review, P1). The
// delivery observer fires once, at the START of an episode — before the
// threshold, so nothing is degraded yet — and every other evaluation hung off a
// /metrics scrape or a /api/diagnostics read. A deployment that configured the
// `siem_feed_down` webhook but does not scrape Prometheus and does not have the
// admin UI open would therefore have its SIEM feed down indefinitely with the
// webhook never firing: the paging surface depended on unrelated HTTP traffic.
//
// Scheduling it removes that dependency entirely. The timer is armed once per
// episode when it opens and stopped on recovery; if the feed recovers first,
// the evaluation runs against a non-degraded snapshot and does nothing, so the
// timer is safe to leave armed. The fire-once latch is unchanged, so a feed
// that stays down still pages exactly once.
//
// A margin is added so the timer cannot land a hair before the threshold and
// evaluate a snapshot that is one nanosecond short of degraded.
func armSyslogDegradeCheck() {
	syslogHealth.mu.Lock()
	if syslogHealth.degradeTimer != nil {
		syslogHealth.degradeTimer.Stop()
	}
	syslogHealth.degradeTimer = syslogScheduleDegradeCheck(
		syslogDegradedAfter+time.Second, evaluateSyslogDegradation)
	syslogHealth.mu.Unlock()
}

// stopSyslogDegradeCheck cancels a pending scheduled evaluation on recovery.
func stopSyslogDegradeCheck() {
	syslogHealth.mu.Lock()
	if syslogHealth.degradeTimer != nil {
		syslogHealth.degradeTimer.Stop()
		syslogHealth.degradeTimer = nil
	}
	syslogHealth.mu.Unlock()
}

// evaluateSyslogDegradation fires the down alert at most once per episode,
// once the feed has been failing for longer than syslogDegradedAfter.
//
// Reached two ways, and it needs both. From the SCHEDULED check above, which is
// what makes the alert independent of anyone looking; and from the surfaces
// that read the state (metrics scrape, diagnostics, /healthz), which makes the
// verdict immediate for a reader and means it can never be latched stale. Same
// discipline as clusterRateLimitFreshness (CHAOS-61) — freshness is EVALUATED,
// never latched — with the timer added so "evaluated" does not quietly mean
// "evaluated only if observed".
func evaluateSyslogDegradation() {
	snap := syslogFeedState()
	if !snap.Degraded {
		return
	}
	syslogHealth.mu.Lock()
	alertNow := !syslogHealth.alerted
	syslogHealth.alerted = true
	syslogHealth.mu.Unlock()
	if !alertNow {
		return
	}
	fireSyslogDownAlert(fmt.Sprintf(
		"SIEM syslog forwarding has been failing for %s (reason: %s, %d records lost); the centralized audit and request trail has a gap for this node — the node-local audit log is unaffected and is the recovery source",
		snap.FailingFor.Round(time.Second), syslogReasonOrUnknown(snap.Reason), snap.Drops))
}

// syslogReasonOrUnknown renders the bounded reason class, defending against an
// empty value (an episode observed through a path that did not record one).
func syslogReasonOrUnknown(r syslog.DropReason) string {
	if r == "" {
		return "unknown"
	}
	return string(r)
}

// syslogFeedSnapshot is the derived view every surface reads.
type syslogFeedSnapshot struct {
	// Configured reports operator INTENT — a target is set — regardless of
	// whether it ever connected.
	Configured bool

	// Live reports whether a Writer actually exists. False when the operator
	// configured a target and the startup connect failed.
	Live bool

	// IntentMatchesLive is false when the live Writer points at a PREVIOUS
	// collector because a later re-init to a new target failed. Preserved from
	// the original checkSyslogFeed, which found this case.
	IntentMatchesLive bool

	// Failing is true while an episode is open (an observed failure with no
	// observed success since). Degraded adds the duration threshold.
	Failing    bool
	Degraded   bool
	FailingFor time.Duration
	Reason     syslog.DropReason

	// LastDelivery is the zero time until the transport accepts its first line.
	LastDelivery time.Time

	Drops    uint64
	ByReason map[syslog.DropReason]uint64
	Panics   uint64
	QueueCap int
	Network  string
	Addr     string

	// DeliveryConfirmable is false on UDP, where a delivery failure is
	// structurally unobservable. Every surface that reports a UDP feed as
	// healthy must say so in the same breath.
	DeliveryConfirmable bool
}

// syslogFeedState derives the current posture from the live Writer's atomics
// plus this file's configured flag.
//
// Reads ONLY atomics on the Writer — never Format(), Close() or anything else
// that takes the engine's mutex. That mutex is held by the drain goroutine
// across the reconnect/backoff state machine, up to ~15s against a collector
// that accepts and never drains, so a surface that took it would block for
// fifteen seconds on exactly the fault it exists to report. Pinned by
// TestChaos66_HealthStateDoesNotBlockOnAWedgedCollector.
func syslogFeedState() syslogFeedSnapshot {
	syslogHealth.mu.Lock()
	configured := syslogHealth.configured
	syslogHealth.mu.Unlock()

	snap := syslogFeedSnapshot{
		Configured: configured || syslogConfiguredAddr != "",
		Addr:       syslogConfiguredAddr,
	}
	w := globalSyslog
	if w == nil {
		return snap
	}
	snap.Live = true
	snap.IntentMatchesLive = syslogConfigured == syslogConfiguredAddr
	snap.Drops = w.Drops()
	snap.Panics = w.Panics()
	snap.ByReason = w.DropsByReason()
	snap.QueueCap = w.QueueCap()
	snap.Network = w.Network()
	snap.DeliveryConfirmable = w.DeliveryConfirmable()
	snap.LastDelivery = w.LastDelivery()
	snap.Reason = w.LastFailureReason()

	if since := w.FailingSince(); !since.IsZero() {
		snap.Failing = true
		snap.FailingFor = syslogHealthNow().Sub(since)
		// A negative span means the clock moved backwards under us (NTP step,
		// VM restore). Report the episode as open but not yet degraded rather
		// than as a huge or negative duration: a clock correction is a fault,
		// not a SIEM outage, and paging on it is noise. Same judgement as
		// threatFeedState's age clamp.
		if snap.FailingFor < 0 {
			snap.FailingFor = 0
		}
		snap.Degraded = snap.FailingFor >= syslogDegradedAfter
	}
	return snap
}

// checkSyslogFeedHealth is the runtime half of the `syslog_feed` operator
// contract row. checkSyslogFeed (diagnostics.go) owns the configured/connected
// half and delegates here once a live Writer exists.
//
// Severity policy:
//   - failing past the threshold → FAIL. Unlike the threat feed (a degraded
//     cache on a fully-enforcing node, hence warn), this is the compliance
//     record going missing, and the register's own ST-8 precedent treats audit
//     loss as the higher-ranked of the two.
//   - failing but inside the threshold → warn. A collector restart is ordinary.
//   - UDP and healthy → ok, with the delivery-assurance limitation stated.
//   - healthy with a drop history → ok, carrying the cumulative count so a
//     PAST episode stays visible after recovery.
func checkSyslogFeedHealth(snap syslogFeedSnapshot) OperatorContractCheck {
	if snap.Degraded {
		return OperatorContractCheck{
			Code:   "syslog_feed",
			Status: diagFail,
			Message: fmt.Sprintf("remote syslog/SIEM forwarding has been FAILING for %s (reason: %s, %d records lost) — audit and request records are not reaching the collector",
				snap.FailingFor.Round(time.Second), syslogReasonOrUnknown(snap.Reason), snap.Drops),
			OperatorAction: "Restore the collector or the network path to it; the feed reconnects automatically and needs no restart. Lost records are NOT retransmitted — recover the gap from this node's local audit log (/api/audit or the audit JSONL). Use POST /api/syslog/test to confirm connectivity once the path is back.",
		}
	}
	if snap.Failing {
		return OperatorContractCheck{
			Code:   "syslog_feed",
			Status: diagWarn,
			Message: fmt.Sprintf("remote syslog/SIEM forwarding is failing (reason: %s, %s so far, %d records lost); reconnecting automatically",
				syslogReasonOrUnknown(snap.Reason), snap.FailingFor.Round(time.Second), snap.Drops),
			OperatorAction: "No action yet — the feed retries on a jittered window and recovers on its own. If it persists past a minute this row escalates and the siem_feed_down alert fires.",
		}
	}
	if !snap.DeliveryConfirmable {
		// The honest UDP verdict. "ok" is right — nothing is known to be wrong
		// — but the message must not let an operator read it as delivery
		// confirmation, because on UDP nothing here can confirm delivery.
		return OperatorContractCheck{
			Code:   "syslog_feed",
			Status: diagOK,
			Message: fmt.Sprintf("remote syslog/SIEM forwarding is configured over UDP (%d records dropped locally). UDP cannot confirm delivery: a dead collector accepts every line silently, so this row reports that the socket is open, NOT that the collector received anything",
				snap.Drops),
			OperatorAction: "If you need delivery assurance for the audit trail, switch the target to tcp:// — over TCP a collector outage is detected, counted by reason, alerted and shown here.",
		}
	}
	if snap.Drops > 0 {
		return OperatorContractCheck{
			Code:   "syslog_feed",
			Status: diagOK,
			Message: fmt.Sprintf("remote syslog/SIEM forwarding is active (%d records lost in earlier episodes: %s)",
				snap.Drops, syslogDropBreakdown(snap)),
		}
	}
	return OperatorContractCheck{
		Code:    "syslog_feed",
		Status:  diagOK,
		Message: "remote syslog/SIEM forwarding is active",
	}
}

// syslogDropBreakdown renders the per-reason counts in the fixed reason order,
// omitting zeros. Deterministic: a map range would reorder the message between
// reads and make the row look like it is changing when it is not.
func syslogDropBreakdown(snap syslogFeedSnapshot) string {
	var parts []string
	for _, r := range syslogReportedReasons {
		if n := snap.ByReason[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", r, n))
		}
	}
	if len(parts) == 0 {
		return "no classified reasons"
	}
	return strings.Join(parts, ", ")
}

// syslogReportedReasons fixes the order in which reasons appear on every
// surface. Mirrors internal/syslog's own dropReasons; pinned against it by
// TestChaos66_ReportedReasonsMatchTheEngine so a reason added to the engine
// cannot be counted and never reported — which would be this sweep's own
// finding, one level down.
var syslogReportedReasons = []syslog.DropReason{
	syslog.DropCollectorUnreachable,
	syslog.DropWriteFailed,
	syslog.DropQueueFull,
	syslog.DropWriterClosed,
	syslog.DropDeliveryPanic,
}

// syslogWritePrometheus appends the culvert_syslog_* delivery series.
//
// Every series is emitted ONLY when a syslog target is configured. A
// `culvert_syslog_up 0` from the large majority of deployments — which forward
// to no SIEM at all — is indistinguishable from a broken feed, and the
// documented paging rule is `== 0`. Same rule as the SOCKS5, cluster-CA and
// DNS gauges.
func syslogWritePrometheus(w *strings.Builder) {
	snap := syslogFeedState()
	if !snap.Configured {
		return
	}
	// Evaluating here as well as in the diagnostics path means a deployment
	// that scrapes but never opens the admin UI still gets the alert.
	evaluateSyslogDegradation()

	w.WriteString("\n# HELP culvert_syslog_up 1 when the SIEM syslog feed is configured and not in a failure episode, 0 while it is failing\n")
	w.WriteString("# TYPE culvert_syslog_up gauge\n")
	fmt.Fprintf(w, "culvert_syslog_up %d\n", boolGauge(snap.Live && !snap.Failing && snap.IntentMatchesLive))

	w.WriteString("\n# HELP culvert_syslog_degraded 1 when the SIEM feed has been failing longer than the degradation threshold\n")
	w.WriteString("# TYPE culvert_syslog_degraded gauge\n")
	fmt.Fprintf(w, "culvert_syslog_degraded %d\n", boolGauge(snap.Degraded))

	// Exported directly as well as the last-delivery timestamp: an episode's
	// length is measured from the first FAILURE, and on a feed that has never
	// delivered there is no timestamp to subtract from — which is precisely the
	// case an operator most needs to alert on.
	w.WriteString("\n# HELP culvert_syslog_failing_seconds Length of the current SIEM feed failure episode in seconds (0 when delivering or idle)\n")
	w.WriteString("# TYPE culvert_syslog_failing_seconds gauge\n")
	fmt.Fprintf(w, "culvert_syslog_failing_seconds %d\n", int64(snap.FailingFor.Seconds()))

	w.WriteString("\n# HELP culvert_syslog_last_delivery_timestamp_seconds Unix time at which the transport last accepted a syslog line (0 = never)\n")
	w.WriteString("# TYPE culvert_syslog_last_delivery_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_syslog_last_delivery_timestamp_seconds %d\n", unixOrZero(snap.LastDelivery))

	// The per-reason breakdown is the point of the counter: "the collector is
	// unreachable" and "the collector is slower than this gateway's line rate"
	// are different faults with different remediations and were one number.
	w.WriteString("\n# HELP culvert_syslog_drops_total Records that never reached the SIEM collector, by bounded reason class\n")
	w.WriteString("# TYPE culvert_syslog_drops_total counter\n")
	for _, r := range syslogReportedReasons {
		fmt.Fprintf(w, "culvert_syslog_drops_total{reason=%q} %d\n", r, snap.ByReason[r])
	}

	// Honesty gauge — see the file header. 0 means no signal on this feed can
	// prove delivery, so `culvert_syslog_up 1` must not be read as confirming
	// it.
	w.WriteString("\n# HELP culvert_syslog_delivery_confirmable 1 when the transport can observe a delivery failure (TCP), 0 when it structurally cannot (UDP)\n")
	w.WriteString("# TYPE culvert_syslog_delivery_confirmable gauge\n")
	fmt.Fprintf(w, "culvert_syslog_delivery_confirmable %d\n", boolGauge(snap.DeliveryConfirmable))

	w.WriteString("\n# HELP culvert_syslog_queue_capacity Capacity of the bounded SIEM delivery queue, so queue_full drops can be read against a known bound\n")
	w.WriteString("# TYPE culvert_syslog_queue_capacity gauge\n")
	fmt.Fprintf(w, "culvert_syslog_queue_capacity %d\n", snap.QueueCap)
}

// syslogDropsByReasonJSON renders the per-reason counts for the admin API in
// the fixed reason order, with every class present even at zero.
//
// Zeros are kept deliberately: a class that disappears when it is zero makes a
// dashboard's columns move, and makes "this fault has not occurred" look
// identical to "this build does not report that fault".
func syslogDropsByReasonJSON(snap syslogFeedSnapshot) map[string]uint64 {
	out := make(map[string]uint64, len(syslogReportedReasons))
	for _, r := range syslogReportedReasons {
		out[string(r)] = snap.ByReason[r]
	}
	return out
}

// syslogHealthzField returns the /healthz value for the SIEM feed, and false
// when there is nothing worth reporting.
//
// Reported, NEVER fatal: a node whose SIEM feed is down is a fully serving
// gateway, and failing the probe would eject it over its logging pipeline.
// See the file header.
func syslogHealthzField() (map[string]any, bool) {
	snap := syslogFeedState()
	if !snap.Configured {
		return nil, false
	}
	if !snap.Failing && snap.Drops == 0 {
		return nil, false
	}
	// Evaluate here too. The scheduled check is what makes the alert
	// independent of readers, but a liveness probe polling /healthz is a
	// reader that costs nothing to honour — and the comment on this plane used
	// to claim /healthz evaluated when it did not (Codex review).
	evaluateSyslogDegradation()
	return map[string]any{
		"failing":  snap.Failing,
		"degraded": snap.Degraded,
		"reason":   syslogReasonOrUnknown(snap.Reason),
		"drops":    snap.Drops,
	}, true
}

// resetSyslogHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so replacing it wholesale under the lock
// would swap the held mutex for an unlocked zero value.
func resetSyslogHealthForTest() {
	syslogHealth.mu.Lock()
	syslogHealth.configured = false
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	if syslogHealth.degradeTimer != nil {
		syslogHealth.degradeTimer.Stop()
		syslogHealth.degradeTimer = nil
	}
	syslogHealth.mu.Unlock()
	setSyslogHealthClockForTest(nil)
	syslogScheduleDegradeCheck = time.AfterFunc
}
