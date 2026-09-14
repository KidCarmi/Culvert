package main

// syslog_health.go — CHAOS-66: the SIEM forwarding plane under a collector that
// goes away.
//
// Why this file exists.
//
// `checkSyslogFeed` already existed, and its own docstring states the problem it
// was written to solve: a configured SIEM feed must not be able to be down
// "with only a single startup log line as signal". It reports exactly one fact —
// whether `InitSyslog` succeeded at the moment it ran — and that fact is green
// for every way the feed can fail AFTER boot, which is every way it actually
// fails in production: the collector is restarted, a firewall rule changes, the
// collector's disk fills and it stops accepting, the VIP moves. Measured against
// the real binary: a TCP collector taken away after a successful boot dial
// dropped 19 audit events while the row kept reporting *"remote syslog/SIEM
// forwarding is active"*.
//
// On UDP it is worse, and UDP is the DEFAULT transport (`InitSyslog` selects it
// whenever the operator writes a bare `host:port`). `net.Dialer.DialContext` on
// UDP resolves and binds; it exchanges no packets, so it cannot fail for any
// resolvable target. The boot dial is therefore not evidence of anything, and
// the row reported a collector that has never existed as active — measured:
// `drops=0`, status `ok`, forever.
//
// So the SIEM feed — the appliance's outbound compliance and forensic record,
// the copy that survives this node being destroyed — had:
//
//   - a health row structurally incapable of reporting its own failure mode;
//   - a `Drops()` counter reaching exactly ONE admin-role JSON blob
//     (`GET /api/syslog`) and nothing that scrapes: no metric, no `/healthz`,
//     no `/ready`, no alert, and not one log line — not even for the first
//     dropped event (CWE-778 / OWASP A09:2021, the same shape ST-8 closed for
//     audit-file writes and §30 closed for the DP→CP audit push queue);
//   - a FLAT 5 s reconnect window with no growth and no jitter, so a fleet
//     re-dials a collector that is by hypothesis already overloaded in
//     lockstep, forever (the closed loop §27 records for the intelligence
//     feeds);
//   - and `Format()` — the accessor behind `GET /api/syslog` — taking the same
//     mutex the drain goroutine holds across dial + write + write, so the admin
//     page an operator opens BECAUSE the SIEM looks wrong hung for ~15 s
//     against a wedged collector.
//
// What this file provides is the observability half; the engine changes are in
// internal/syslog. Surfaces, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the `syslog_feed` operator-contract row, rewritten
//     to report OBSERVED DELIVERY instead of the boot dial.
//   - `/healthz` — the `syslogFeed` posture field.
//   - `/metrics` — culvert_syslog_{up,delivered_total,drops_total,
//     queue_full_total,degraded,last_success_age_seconds,backoff_seconds}.
//   - alerts — `siem_feed_degraded`.
//
// Deliberately NOT on `/ready` or `/readyz`. A node whose SIEM collector is
// unreachable is proxying perfectly; failing readiness would eject a healthy
// gateway from the load balancer over its log feed, converting a monitoring
// outage into a traffic outage. That is the same trade §19 refused for the
// category store and §25 for the admin UI listener.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// syslogFeedDegradedAfter and syslogFeedLogInterval are constants in spirit —
// nothing in production writes them, and there is deliberately no config
// surface: the only use for a knob here would be widening the window in which a
// dead compliance feed looks healthy. They are declared as vars ONLY so the
// chaos gates can compress a 60-second threshold into a test that runs in
// milliseconds, and are read through the atomics below rather than directly,
// because both are read from BACKGROUND goroutines — the engine's drain
// goroutine and the degradation timer. A plain var that only tests write is
// still a data race when a previous test's drain goroutine is reading it as the
// next test's cleanup restores it (caught by `-race -shuffle=on -count=2`).
var (
	// syslogFeedDegradedAfter is how long delivery must have been failing
	// UNINTERRUPTED before the feed is reported degraded (warn/fail row, alert,
	// gauge).
	//
	// A DURATION, not a count — the same rule as socks5AcceptDegradedAfter and
	// adminUIUnavailableAfter. A count would page on a single collector restart
	// on a busy node (one drop per proxied request means a 2-second restart is
	// thousands of "failures"), and would page later, or never, on a quiet one.
	// Sixty seconds of uninterrupted failure is no longer a collector bounce.
	syslogFeedDegradedAfter = 60 * time.Second

	// syslogFeedLogInterval rate-limits the delivery-failure log line. The FIRST
	// failure of an episode is logged immediately (an operator must see the
	// onset), then at most one line per interval, then one recovery line
	// carrying the suppressed count.
	//
	// This mitigation must not become the defect it mitigates: a gateway emits
	// one request-log line per proxied request through this feed, so an
	// unthrottled failure line would put the fault's own volume into the process
	// log — the CHAOS-54 write-amplification shape, which on a 50 MB rotating
	// file with one archive destroys the evidence of the cause.
	syslogFeedLogInterval = 60 * time.Second
)

// degradedAfterNanos/alertSink are the safely-published forms of the two knobs
// above. Initialised from the vars at init so production behaviour is identical.
var (
	degradedAfterNanos atomic.Int64
	alertSink          atomic.Pointer[func(string)]
)

func init() {
	degradedAfterNanos.Store(int64(syslogFeedDegradedAfter))
	f := defaultSyslogFeedAlert
	alertSink.Store(&f)
}

// syslogDegradedAfter returns the live degradation threshold.
func syslogDegradedAfter() time.Duration { return time.Duration(degradedAfterNanos.Load()) }

// setSyslogDegradedAfterForTest compresses the threshold. Test isolation only;
// callers restore the package default (syslogFeedDegradedAfter) in a cleanup
// rather than threading a previous value back.
func setSyslogDegradedAfterForTest(d time.Duration) { degradedAfterNanos.Store(int64(d)) }

// setSyslogFeedAlertSinkForTest swaps the alert delivery function so a test can
// observe transitions synchronously. Test isolation only; callers restore
// defaultSyslogFeedAlert in a cleanup.
func setSyslogFeedAlertSinkForTest(fn func(string)) { alertSink.Store(&fn) }

// fireSyslogFeedAlert dispatches through the published sink.
func fireSyslogFeedAlert(detail string) {
	if p := alertSink.Load(); p != nil {
		(*p)(detail)
	}
}

// syslogFeedHealth holds only what cannot be derived from the engine's delivery
// record: the log rate gate and the fire-once alert latch. Everything factual
// (delivered, drops, consecutive failures, when the run started, the bounded
// reason) lives in internal/syslog and is read LOCK-FREE, so no reporting
// surface can ever block behind the collector socket it is reporting on.
type syslogFeedHealth struct {
	mu sync.Mutex

	// logAt gates the failure log line; suppressed counts what the gate
	// swallowed since the last emitted line, so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per DEGRADATION episode: one page when the
	// feed has been dark past the threshold, not one per dropped line. Cleared
	// only by an OBSERVED delivery, so a second outage pages again.
	alerted bool

	// degradeTimer re-evaluates the threshold when no further delivery event is
	// coming (Codex review, PR #1384). The alert used to be decided ONLY inside
	// the delivery observer, which runs only when a line is submitted — so a
	// collector that dies and is followed by an IDLE node left the last failure
	// event carrying a near-zero FailingFor and nothing ever looked again, while
	// syslogFeedState (which derives degradation from the wall clock) started
	// reporting the feed degraded at the threshold regardless. The contract row
	// and the gauge said degraded; the page never fired.
	//
	// That is exactly the disagreement this file's design note claimed was
	// impossible, and it is the MIRROR IMAGE of the rule the sweep got right on
	// the other side: recovery must not be declared by silence, and degradation
	// must not be suppressed by it. Measured pre-fix: degraded=true,
	// failingFor=3s, zero alerts.
	//
	// One timer per EPISODE, not per failure. Its callback re-reads the live
	// delivery record, so a feed that recovered while it was pending alerts
	// nothing — the evidence rule is preserved, not bypassed.
	degradeTimer *time.Timer

	// addr is this record's OWN copy of the configured collector, published by
	// armSyslogFeedHealth under this mutex.
	//
	// The observer below runs on the engine's drain goroutine, and
	// syslogConfiguredAddr is a plain string global that the admin HTTP
	// goroutine rewrites (POST /api/syslog). Reading it from a background
	// goroutine would add a data race to report on the very subsystem this
	// sweep is about, so the observer reads this copy and everything else it
	// needs off the DeliveryOutcome the engine hands it. The HTTP-goroutine
	// surfaces keep reading the globals exactly as they always have.
	addr string
}

var syslogFeed syslogFeedHealth

// fireSyslogFeedAlert delivers the `siem_feed_degraded` alert.
//
// A NEW event name rather than a reused one. The house rule is to reuse
// existing vocabulary when the OPERATOR ACTION is the same (which is why an
// expired cluster CA rides `cert_expiry` and a stale threat feed does not get a
// second dialect) — but "your SIEM collector is unreachable" and "this node's
// disk is failing" send an operator to different systems, so folding this into
// `storage_write_failed` would be one page for two actions.
//
// Swappable (see setSyslogFeedAlertSinkForTest) so tests observe transitions
// SYNCHRONOUSLY instead of racing the process-global alerts sink.
// HasSubscriber-gated for the reason documented on fireStorageWriteAlert: with
// no webhook configured — the default posture, and the state of every test
// binary — this must not spawn a goroutine at all.
func defaultSyslogFeedAlert(detail string) {
	if !globalAlertStore.HasSubscriber("siem_feed_degraded") {
		return
	}
	go fireAlert("siem_feed_degraded", AlertPayload{
		Detail: detail,
		Source: "syslog",
	})
}

// noteSyslogDelivery is the delivery observer wired into every Writer this
// process builds (see newSyslogWriter). It runs SYNCHRONOUSLY on the engine's
// drain goroutine and is only ever called on a FAILURE or on the first delivery
// that lands after a failing run — never on the healthy per-line path.
func noteSyslogDelivery(out syslogDeliveryOutcome) {
	if out.OK {
		noteSyslogFeedRecovered(out)
		return
	}
	noteSyslogFeedFailure(out)
}

// noteSyslogFeedFailure records one undelivered line, emitting at most one log
// line per syslogFeedLogInterval and at most one alert per episode.
//
// Degradation is read from the ENGINE's record rather than recomputed here, so
// the alert, the gauge and the contract row can never disagree about whether
// the feed is degraded.
func noteSyslogFeedFailure(out syslogDeliveryOutcome) {
	// Degradation is judged from the ENGINE's own record, carried on the
	// outcome, so the alert, the gauge and the contract row can never disagree
	// about whether the feed is degraded.
	degraded := out.FailingFor >= syslogDegradedAfter()

	syslogFeed.mu.Lock()
	addr := syslogFeed.addr
	if addr == "" {
		syslogFeed.mu.Unlock()
		return
	}
	now := time.Now()
	shouldLog := syslogFeed.logAt.IsZero() || now.Sub(syslogFeed.logAt) >= syslogFeedLogInterval
	if shouldLog {
		syslogFeed.logAt = now
	} else {
		syslogFeed.suppressed++
	}
	alertNow := degraded && !syslogFeed.alerted
	if alertNow {
		syslogFeed.alerted = true
	}
	// Not degraded YET: arm a one-shot re-evaluation for the moment the
	// threshold elapses, in case this is the last line the node ever submits.
	if !degraded && !syslogFeed.alerted && syslogFeed.degradeTimer == nil {
		remaining := syslogDegradedAfter() - out.FailingFor
		if remaining < time.Millisecond {
			remaining = time.Millisecond
		}
		syslogFeed.degradeTimer = time.AfterFunc(remaining, evaluateSyslogFeedDegradation)
	}
	syslogFeed.mu.Unlock()

	if shouldLog {
		// Checked, because it is the failure mode this line could create:
		// `logger` composes stdout + the rotating process-log file and does NOT
		// include the syslog writer (see setupLogger), so a delivery-failure
		// line cannot itself become a line to deliver. If the syslog writer is
		// ever added to the process-log chain, this call becomes a feedback
		// loop and must move behind a guard.
		//
		// The bounded reason class goes everywhere; the collector address goes
		// only here, where it is already in the operator's own configuration.
		logger.Printf("WARN SIEM_FEED_DEGRADED: syslog delivery to %q failing (reason=%s, %d consecutive, %d events lost, retry in %s)",
			sanitizeLog(addr), sanitizeLog(out.Reason), out.Consecutive, out.Drops, out.Backoff.Round(time.Second))
	}
	if alertNow {
		fireSyslogFeedAlert(fmt.Sprintf(
			"SIEM syslog forwarding has been failing for over %s (reason: %s, %d events lost); security and audit events are NOT reaching the collector, and the local copy is this node's only record",
			syslogDegradedAfter(), out.Reason, out.Drops))
	}
}

// evaluateSyslogFeedDegradation runs when the degradation threshold elapses with
// no further delivery event. It re-reads the LIVE record rather than trusting
// the state that armed it, so a feed that recovered in the meantime pages
// nothing — degradation is still established by failure evidence, never by a
// timer alone.
//
// Reads no plain process globals: the collector address comes from this
// record's own mutex-protected copy and the evidence from the active Writer's
// lock-free Stats(), for the same reason the observer does (see addr above).
func evaluateSyslogFeedDegradation() {
	sw := activeSyslog()
	var degraded, stillFailing bool
	var drops uint64
	var reason string
	var shortBy time.Duration
	if sw != nil {
		st := sw.Stats()
		if !st.FirstFail.IsZero() {
			stillFailing = true
			if elapsed := time.Since(st.FirstFail); elapsed >= syslogDegradedAfter() {
				degraded, drops, reason = true, st.Drops, st.LastReason
			} else {
				shortBy = syslogDegradedAfter() - elapsed
			}
		}
	}

	syslogFeed.mu.Lock()
	syslogFeed.degradeTimer = nil
	alertNow := degraded && syslogFeed.addr != "" && !syslogFeed.alerted
	if alertNow {
		syslogFeed.alerted = true
	}
	// Still failing but the threshold has not actually elapsed: re-arm rather
	// than give up. FirstFail is reconstructed from stored nanoseconds, so it
	// carries NO monotonic reading and time.Since on it is wall-clock — an NTP
	// step backwards between arming and firing lands here. Without the re-arm
	// the one shot is spent and, on an idle node, nothing would ever look again:
	// a clock correction would silently cost the operator the page. Only one
	// timer is ever outstanding, and recovery or a reconfigure stops it.
	if !degraded && stillFailing && syslogFeed.addr != "" && !syslogFeed.alerted && syslogFeed.degradeTimer == nil {
		if shortBy < time.Millisecond {
			shortBy = time.Millisecond
		}
		syslogFeed.degradeTimer = time.AfterFunc(shortBy, evaluateSyslogFeedDegradation)
	}
	syslogFeed.mu.Unlock()

	if alertNow {
		fireSyslogFeedAlert(fmt.Sprintf(
			"SIEM syslog forwarding has been failing for over %s (reason: %s, %d events lost); security and audit events are NOT reaching the collector, and the local copy is this node's only record",
			syslogDegradedAfter(), reason, drops))
	}
}

// stopDegradeTimerLocked cancels a pending threshold re-evaluation. Caller must
// hold syslogFeed.mu.
func stopDegradeTimerLocked() {
	if syslogFeed.degradeTimer != nil {
		syslogFeed.degradeTimer.Stop()
		syslogFeed.degradeTimer = nil
	}
}

// noteSyslogFeedRecovered clears the episode on OBSERVED delivery — a line the
// collector socket actually accepted.
//
// Elapsed time never clears it, and that is load-bearing here for a reason the
// other health planes do not have: this feed's traffic is generated by proxied
// requests, so a feed that "stopped failing" on an idle node is
// indistinguishable from a working one. Only an accepted write is evidence.
func noteSyslogFeedRecovered(out syslogDeliveryOutcome) {
	if !out.Recovered {
		return
	}
	syslogFeed.mu.Lock()
	suppressed := syslogFeed.suppressed
	wasAlerted := syslogFeed.alerted
	hadEpisode := !syslogFeed.logAt.IsZero()
	addr := syslogFeed.addr
	syslogFeed.logAt = time.Time{}
	syslogFeed.suppressed = 0
	syslogFeed.alerted = false
	stopDegradeTimerLocked()
	syslogFeed.mu.Unlock()

	if !hadEpisode && !wasAlerted {
		return
	}
	logger.Printf("SIEM_FEED_RECOVERED: syslog delivery to %q resumed (%d events lost during the outage, %d further failure lines suppressed)",
		sanitizeLog(addr), out.Drops, suppressed)
}

// syslogFeedSnapshot is the view handed to every reporting surface.
type syslogFeedSnapshot struct {
	// Configured reflects operator INTENT (syslogConfiguredAddr), recorded
	// regardless of whether InitSyslog succeeded — so "never configured" and
	// "configured but the writer could not be built" stay distinguishable.
	//
	// The collector ADDRESS is deliberately NOT on this snapshot: its consumers
	// are the viewer-role contract row, /metrics and /healthz, none of which may
	// carry an operator-configured endpoint. The one place that needs it — the
	// rate-limited failure log line — reads the health record's own copy.
	Configured bool

	// Active is false when intent exists but no writer is serving it: the boot
	// dial failed, or a later re-init to a new target failed and left the
	// previous writer pointing at a collector the operator has moved on from.
	Active bool

	Delivered   uint64
	Drops       uint64
	QueueFull   uint64
	Consecutive int64
	LastReason  string
	// EverDelivered is false when NOTHING has ever reached the collector. On
	// TCP that is a misconfiguration; on UDP it is the only signal available
	// that the target may not exist.
	EverDelivered  bool
	LastSuccessAge time.Duration
	Failing        bool
	FailingFor     time.Duration
	Degraded       bool
	Backoff        time.Duration
	// Unverifiable is true for UDP: the protocol carries no acknowledgement, so
	// a write that the socket accepted is not evidence the collector received
	// anything. Reported rather than papered over.
	Unverifiable bool
}

// syslogFeedState assembles the snapshot. Never blocks: every engine field it
// reads is an atomic or an immutable, precisely so the diagnostics row cannot
// queue behind a wedged collector.
func syslogFeedState() syslogFeedSnapshot {
	snap := syslogFeedSnapshot{Configured: syslogConfiguredAddr != ""}
	sw := activeSyslog()
	// syslogConfigured is set SOLELY on a successful InitSyslog; comparing it
	// against intent catches the case where an earlier target is still being
	// served after a failed re-init (see the original checkSyslogFeed note).
	if sw == nil || syslogConfigured != syslogConfiguredAddr {
		return snap
	}
	snap.Active = true
	st := sw.Stats()
	snap.Unverifiable = st.Network == "udp"
	snap.Delivered = st.Delivered
	snap.Drops = st.Drops
	snap.QueueFull = st.QueueFull
	snap.Consecutive = st.Consecutive
	snap.LastReason = st.LastReason
	snap.Backoff = st.Backoff
	if !st.LastSuccess.IsZero() {
		snap.EverDelivered = true
		snap.LastSuccessAge = time.Since(st.LastSuccess)
	}
	if !st.FirstFail.IsZero() {
		snap.Failing = true
		snap.FailingFor = time.Since(st.FirstFail)
		snap.Degraded = snap.FailingFor >= syslogDegradedAfter()
	}
	return snap
}

// armSyslogFeedHealth publishes the collector this record is reporting on and
// clears the log gate and the alert latch. Called by InitSyslog on every
// (re)configure: a new writer starts a new delivery record, so a reconfigure
// onto a healthy collector must not inherit the previous target's fired alert
// and then never page again.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so replacing the whole value under the lock
// would leave the following Unlock operating on a different, unlocked mutex.
func armSyslogFeedHealth(addr string) {
	syslogFeed.mu.Lock()
	defer syslogFeed.mu.Unlock()
	syslogFeed.addr = addr
	syslogFeed.logAt = time.Time{}
	syslogFeed.suppressed = 0
	syslogFeed.alerted = false
	stopDegradeTimerLocked()
}

// resetSyslogFeedHealth clears the record entirely (forwarding disabled, or
// test isolation). With no address published the observer no-ops, so a writer
// that outlives its configuration cannot log or page about a feed the operator
// has already turned off.
func resetSyslogFeedHealth() { armSyslogFeedHealth("") }

// syslogFeedStatus is the /healthz posture string.
//
// "disabled" when no feed is configured, so the field never reads as a fault on
// the majority of appliances that forward nowhere.
func syslogFeedStatus() string {
	snap := syslogFeedState()
	switch {
	case !snap.Configured:
		return "disabled"
	case !snap.Active:
		return "down"
	case snap.Degraded:
		return "degraded"
	case snap.Failing:
		return "failing"
	default:
		return "ready"
	}
}
