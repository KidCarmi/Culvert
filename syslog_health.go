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

	// target is the operator-facing collector address, kept only to name the
	// transport in the UDP caveat. Never reaches an alert Detail.
	target string

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
	syslogHealth.configured = true
	syslogHealth.installedAt = syslogHealthNow()
	syslogHealth.target = target
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()

	sw.SetDeliveryObserver(noteSyslogDelivery)
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
	syslogHealth.configured = false
	syslogHealth.installedAt = time.Time{}
	syslogHealth.target = ""
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
	snap := syslogFeedState()
	if !snap.Degraded {
		return
	}

	syslogHealth.mu.Lock()
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

	if shouldLog && logger != nil {
		logger.Printf("WARN syslog: SIEM feed not delivering — no line has reached the collector for %s (%d lines dropped, last failure %q); audit and request events are NOT reaching the SIEM",
			snap.Age.Round(time.Second), snap.Drops, sanitizeLog(snap.Reason))
	}
	if alertNow {
		fireSyslogFeedDownAlert(fmt.Sprintf(
			"the remote syslog/SIEM feed has delivered nothing for %s (%d events dropped, reason: %s); audit and request events are not reaching the collector while the node keeps proxying normally",
			snap.Age.Round(time.Second), snap.Drops, reasonOrUnknown(snap.Reason)))
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
	// Configured is true once a Writer has been installed. Distinct from the
	// operator INTENT recorded in syslogConfiguredAddr, which is set even when
	// the initial dial failed.
	Configured bool
	// NeverDelivered is true when this Writer has never got a line out.
	NeverDelivered bool
	// Degraded is the paging predicate: lines are being lost AND nothing has
	// been delivered for syslogDegradedAfter.
	Degraded bool
	// Age is the time since the last delivered line, or since the Writer was
	// installed when nothing has ever been delivered.
	Age         time.Duration
	LastSuccess time.Time
	Delivered   uint64
	Drops       uint64
	Panics      uint64
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
	syslogHealth.mu.Unlock()

	snap := syslogFeedSnapshot{
		Configured: configured,
		UDP:        !strings.HasPrefix(strings.ToLower(target), "tcp://"),
	}
	sw := activeSyslog()
	if !configured || sw == nil {
		return snap
	}
	st := sw.Stats()
	snap.Delivered = st.Delivered
	snap.Drops = st.Drops
	snap.Panics = st.Panics
	snap.ConsecutiveFailures = st.ConsecutiveFailures
	snap.Reason = st.LastFailureReason
	snap.QueueDepth = st.QueueDepth
	snap.QueueCap = st.QueueCap
	snap.LastSuccess = st.LastSuccess

	now := syslogHealthNow()
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
		return OperatorContractCheck{
			Code:   "syslog_feed",
			Status: diagFail,
			Message: fmt.Sprintf("remote syslog/SIEM forwarding is DOWN: %s and %d event(s) have been dropped (last failure: %s). Audit and request events are not reaching the SIEM; the node keeps proxying normally and the local audit log is unaffected",
				what, snap.Drops, reasonOrUnknown(snap.Reason)),
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
		case snap.NeverDelivered:
			// No delivery has EVER happened, so there is no "last event" to
			// date and no delivery to claim. Distinct from the degraded branch
			// only by how long it has been failing.
			return OperatorContractCheck{
				Code:   "syslog_feed",
				Status: diagWarn,
				Message: fmt.Sprintf("remote syslog/SIEM forwarding has NEVER delivered an event since this target was configured %s ago, and %d event(s) have already been dropped (last failure: %s)",
					snap.Age.Round(time.Second), snap.Drops, reasonOrUnknown(snap.Reason)),
				OperatorAction: "Treat this as a misconfigured or unreachable target rather than a transient stall: check the host/port, that the collector is listening, the network path, and for tcp:// the collector's connection limit. Confirm with POST /api/syslog/test. Nothing has reached the SIEM yet, and the dropped events are not replayed.",
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
	if !snap.Configured {
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
	w.WriteString("\n# HELP culvert_syslog_drops_total Events lost before reaching the remote syslog/SIEM collector (collector down, queue overflow, or writer closed)\n")
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
	syslogHealth.configured = false
	syslogHealth.installedAt = time.Time{}
	syslogHealth.target = ""
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	syslogHealth.mu.Unlock()
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
