package main

// syslog_health.go — the SIEM/syslog forwarding plane's DELIVERY health
// (CHAOS-66).
//
// # Why this file exists
//
// Before this file, the product answered one question about the SIEM feed —
// "did InitSyslog's dial return nil?" — and presented the answer as though it
// were the other question, "are security events reaching the collector?".
//
// Those are not the same question, and for the DEFAULT transport they are not
// even related. InitSyslog defaults to UDP when the operator omits a scheme,
// and net.Dial("udp", …) sends nothing: it resolves the address, binds a
// socket, and returns success whether or not anything is listening. Measured
// against the real dialer:
//
//	udp dial to a dead local port      → conn, err=<nil>
//	udp dial to a remote blackhole     → conn, err=<nil>
//	  … and every subsequent write     → n=10, err=<nil>, forever
//
// So on a UDP collector — the default, and the common enterprise shape, where
// the SIEM sits on another network and ICMP unreachables are filtered — a
// gateway can discard 100% of its audit and request feed while:
//
//   - `syslog_feed` on /api/diagnostics reports ok, "remote syslog/SIEM
//     forwarding is active";
//   - Drops() reports 0, because no write ever failed; and
//   - /metrics carries no syslog series at all, so no alerting rule can be
//     written even by an operator who knows to look.
//
// The TCP case is better only in that the loss is countable. A collector that
// goes away at runtime leaves globalSyslog non-nil and syslogConfigured equal
// to intent, so checkSyslogFeed's existing branches all pass and the row stays
// green while deliverLine counts a drop for every line and re-dials every 5s,
// forever, without ever emitting a log line. That retry is unbounded in count
// AND silent, which is the one shape CHAOS-54/55/57/59 each concluded was not
// acceptable: "avoid infinite retries" is satisfied by a retry that is
// RATE-bounded and LOUD, never by one nobody can see.
//
// The feed carries the audit trail and the request log to the customer's
// compliance system. Losing it silently is CWE-778 / OWASP A09:2021 on the
// record an auditor reads, and it is the same defect CHAOS-61 closed for the
// DP→CP audit push queue one subsystem over — that queue dropped with no
// counter, metric or log line, and the fix there was to count it, name the
// reason, and put it on /metrics. This is that fix for the SIEM feed, plus the
// part CHAOS-61 did not have to face: a transport on which loss cannot be
// observed at all.
//
// # What this file adds
//
// The shape storage_health.go, ca_health.go, socks5_health.go and
// threatfeed_health.go use, and deliberately no new operator vocabulary:
//
//   - /metrics — culvert_syslog_{up,delivering,delivery_verifiable,
//     delivered_total,drops_total{reason},last_delivery_timestamp_seconds,
//     consecutive_failures}, emitted ONLY when a SIEM target is configured.
//   - /api/diagnostics — the `syslog_feed` row now verdicts on DELIVERY, and
//     states plainly when delivery is unverifiable rather than reporting the
//     absence of observed failures as success.
//   - alerts — `siem_forwarding_failing`, fire-once per episode, recovered on
//     OBSERVED evidence (a line the socket accepted), never on elapsed time.
//   - the process log — the onset immediately, then at most one line per
//     interval, then one recovery line naming the suppressed count.
//
// # What it deliberately does NOT add
//
// **No /readyz row and no /healthz failure.** A node whose SIEM collector is
// unreachable is a fully serving gateway: policy, inspection, scanning and the
// LOCAL audit JSONL are all unaffected. Failing readiness would eject a
// healthy gateway from the load balancer over its logging pipeline — the
// judgement §19 recorded for the category store and §27 for the threat feed,
// and the inverse of the outage CHAOS-57 exists to prevent.
//
// **No fail-closed toggle.** Blocking traffic because a log collector is down
// converts the SIEM's outage into the customer's outage. The feed is a
// duplicate of a record this node already persists locally.
//
// **No metric for UDP "success".** culvert_syslog_delivering is deliberately
// NOT emitted as a green 1 on UDP. "Found nothing wrong" and "never checked"
// are the same scrape — the lesson §35 recorded for OCSP coverage — so the
// verifiable/unverifiable fact is exported as its own series and the liveness
// gauge is absent where it would be a fiction.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// syslogDeliveryDegradedAfter is how long the feed must be FAILING
	// CONTINUOUSLY before it is reported as degraded and paged on.
	//
	// A DURATION, not a count, for the reason socks5_health.go and
	// admin_ui_health.go both record: the drop count during an outage tracks
	// the gateway's traffic rate, so a count threshold pages instantly on a
	// busy node and never on a quiet one for the very same fault. A collector
	// restart or a brief network blip is an ordinary operation and must not
	// page; a minute of continuous failure is not a blip.
	syslogDeliveryDegradedAfter = 60 * time.Second

	// syslogLogInterval rate-limits the failure log line: onset immediately,
	// then at most one line per interval, then one recovery line naming the
	// suppressed count. The log carries the SIGNAL, the counter carries the
	// MAGNITUDE — storage_health.go's discipline, and the reason a mitigation
	// for a logging defect does not become a write-amplification one itself.
	syslogLogInterval = 5 * time.Minute
)

// syslogHealthRecord is the process-wide record of SIEM delivery health.
//
// It holds only what internal/syslog cannot: the operator's intent, the
// episode anchor, and the edge-triggered alert/log gates. The counters, the
// last delivery and the bounded failure reason are read live from the Writer's
// own Health() snapshot, so there is exactly one source of truth and no chance
// of the two drifting.
type syslogHealthRecord struct {
	mu sync.Mutex

	// configured is false until a SIEM target is in effect. Every surface
	// reports the feature as absent then, rather than exporting a zero that is
	// indistinguishable from a broken feed — the CHAOS-54 rule, and the reason
	// the socks5/cluster_ca/dns gauges are all emitted conditionally.
	configured bool

	// owner is the writer this record describes, and it is the FENCE against a
	// callback from a retired one (Codex review, PR #1430).
	//
	// retireSyslogWriter clears the old writer's observer pointer, but that
	// only stops callbacks that have not yet LOADED it. A drain goroutine
	// already inside notifyDelivery holds the old pointer and can be
	// descheduled there arbitrarily long — past the swap, past
	// noteSyslogConfigured — and then write into the record that now describes
	// the NEW writer: a healthy replacement reported as failing, or a real
	// outage silently cleared by a stale recovery edge.
	//
	// Identity is the fence rather than a generation counter because it cannot
	// be spoofed, needs no plumbing (the writer is in scope where the observer
	// is installed), and is checked INSIDE the same critical section that
	// mutates — a check in a separate lock acquisition would be the same race
	// one level up.
	owner *syslogWriter

	// failingSince anchors the degradation DURATION. Zero means not currently
	// failing. Set on the first collector-attributable failure of an episode
	// and cleared only by an observed delivery.
	failingSince time.Time

	// alerted latches the page for the duration of one episode so a collector
	// that stays down does not re-page per dropped line.
	alerted bool

	// lastReason is the bounded class of the most recent failure, kept so the
	// threshold timer can name a cause it did not observe itself.
	lastReason string

	// alertTimer fires the page when an episode crosses the threshold with no
	// further traffic to carry it (Codex review, PR #1430). Without it,
	// `alertNow` was only ever evaluated while processing ANOTHER failed line,
	// so a gateway that loses one line and then goes quiet — a standby node, a
	// quiet night — would cross the threshold with /metrics and
	// /api/diagnostics both reporting the episode as degraded while the
	// webhook never fired. Two surfaces disagreeing about one condition is the
	// defect CHAOS-61 rule (2) names by hand.
	//
	// It is armed once per episode and stopped by recovery, reconfiguration or
	// disable. It only TRIGGERS a re-evaluation; the decision still reads
	// syslogNow(), so a test clock governs the verdict and a real-clock timer
	// firing under a frozen test clock correctly decides nothing.
	alertTimer *time.Timer

	// logAt / suppressed drive the rate-limited log line.
	logAt      time.Time
	suppressed int64
}

var syslogHealth syslogHealthRecord

// syslogNow is the clock seam, and syslogAlertFn the alert seam. Both are
// ATOMIC rather than the plain package vars the other health planes use, and
// that difference is load-bearing rather than stylistic.
//
// noteSyslogDelivery runs on the syslog DRAIN goroutine — it is invoked by the
// writer's delivery observer, not by the goroutine under test — so a test that
// swaps either seam races a live writer. The plain-var seams elsewhere in this
// tree (threatFeedNow, fireThreatFeedStaleAlert) are only ever read on the same
// goroutine that swaps them, which is why they can stay plain. Caught by -race;
// a plain var here passes every functional gate and fails CI.
var (
	syslogNowFn   atomic.Pointer[func() time.Time]
	syslogAlertFn atomic.Pointer[func(detail string)]
)

// syslogNow reports the current time through the seam, defaulting to the real
// clock when no test clock is installed.
func syslogNow() time.Time {
	if p := syslogNowFn.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
}

// setSyslogNow installs a test clock (nil restores the real one).
func setSyslogNow(fn func() time.Time) {
	if fn == nil {
		syslogNowFn.Store(nil)
		return
	}
	syslogNowFn.Store(&fn)
}

// setSyslogAlert installs a test alert sink (nil restores the real one).
func setSyslogAlert(fn func(detail string)) {
	if fn == nil {
		syslogAlertFn.Store(nil)
		return
	}
	syslogAlertFn.Store(&fn)
}

// fireSyslogFailingAlert delivers the `siem_forwarding_failing` alert.
//
// Overridable through setSyslogAlert so tests observe transitions synchronously
// rather than racing the process-global alerts sink (the -count/-shuffle
// determinism class the CI gate catches). The override lives in an atomic, not
// a plain var, because this function is reached from the syslog DRAIN
// goroutine — see the seam declaration above. HasSubscriber-gated for the
// reason documented on fireStorageWriteAlert: with no webhook configured — the default posture, and
// the state of every test binary — this must not spawn a goroutine at all.
//
// The Detail carries the BOUNDED reason class from internal/syslog, never a
// raw error: Dispatch dedups on event+Detail, and a net error embeds the
// collector address and the ephemeral local port, so a per-attempt-unique
// Detail would defeat the dedup window by construction and evict real threat
// alerts from the 500-entry retry queue (WK-12/RS-5). The reason is an enum in
// the engine, so this is structural rather than a convention to remember.
//
// A NEW event name is justified here despite the standing preference for
// reusing one (a new name is unsubscribed on every already-configured
// webhook): no existing event covers "your SIEM is not receiving events", and
// the nearest candidate, storage_write_failed, names a LOCAL volume fault with
// an entirely different remedy. The name is added to the webhook event picker
// in the same change so it is subscribable from the GUI.
func fireSyslogFailingAlert(detail string) {
	if p := syslogAlertFn.Load(); p != nil {
		(*p)(detail)
		return
	}
	if !globalAlertStore.HasSubscriber("siem_forwarding_failing") {
		return
	}
	go fireAlert("siem_forwarding_failing", AlertPayload{
		Detail: detail,
		Source: "syslog",
	})
}

// noteSyslogConfigured records that a SIEM target is in effect, takes ownership
// for sw, and resets the episode state. Called from every path that installs a
// Writer.
//
// Taking ownership is what makes a retired writer's in-flight callback
// harmless: from here on, only sw may move this record.
func noteSyslogConfigured(sw *syslogWriter) {
	syslogHealth.mu.Lock()
	syslogHealth.configured = true
	syslogHealth.owner = sw
	syslogHealth.failingSince = time.Time{}
	syslogHealth.alerted = false
	syslogHealth.lastReason = ""
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	stopSyslogAlertTimerLocked()
	syslogHealth.mu.Unlock()
}

// stopSyslogAlertTimerLocked disarms the threshold timer. Caller holds mu.
//
// Stop() may return false for a timer whose callback has already started; that
// is harmless here, because the callback re-reads the episode state under the
// lock and a reset episode decides nothing.
func stopSyslogAlertTimerLocked() {
	if syslogHealth.alertTimer != nil {
		syslogHealth.alertTimer.Stop()
		syslogHealth.alertTimer = nil
	}
}

// noteSyslogUnconfigured clears the plane when forwarding is disabled, so a
// disabled feed never keeps exporting series or holding a latched alert.
func noteSyslogUnconfigured() {
	syslogHealth.mu.Lock()
	syslogHealth.configured = false
	syslogHealth.owner = nil
	syslogHealth.failingSince = time.Time{}
	syslogHealth.alerted = false
	syslogHealth.lastReason = ""
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	stopSyslogAlertTimerLocked()
	syslogHealth.mu.Unlock()
}

// noteSyslogDelivery is the delivery observer: called on every
// collector-attributable failure and on the recovery edge. It runs on the
// syslog drain goroutine of the writer w it was installed on.
//
// w is FENCED against the record's current owner, inside the same critical
// section that mutates it. A retired writer's callback — one already past
// notifyDelivery's pointer load when the swap happened — therefore returns
// having touched nothing, instead of driving the episode state of the writer
// that replaced it (Codex review, PR #1430; the non-racy half is SL-8).
//
// It must never write to the process log through a path that reaches the
// syslog writer, and it never calls back into the Writer — the same rule
// audit.SetWriteFailureObserver carries, for the same unbounded-recursion
// reason, and walled by TestChaos66_Wall_DeliveryObserverCannotRecurse.
func noteSyslogDelivery(w *syslogWriter, ok bool, reason string, consecutive int64) {
	if ok {
		noteSyslogDeliveryRecovered(w)
		return
	}
	now := syslogNow()

	syslogHealth.mu.Lock()
	if syslogHealth.owner != w {
		// A superseded writer speaks for nobody.
		syslogHealth.mu.Unlock()
		return
	}
	if syslogHealth.failingSince.IsZero() {
		syslogHealth.failingSince = now
		// Arm the threshold timer ONCE per episode, so the page does not
		// depend on more traffic arriving to carry it.
		syslogHealth.alertTimer = time.AfterFunc(syslogDeliveryDegradedAfter, evaluateSyslogEpisode)
	}
	syslogHealth.lastReason = reason
	shouldLog := syslogHealth.logAt.IsZero() || now.Sub(syslogHealth.logAt) >= syslogLogInterval
	if shouldLog {
		syslogHealth.logAt = now
	} else {
		syslogHealth.suppressed++
	}
	syslogHealth.mu.Unlock()

	if shouldLog && logger != nil {
		logger.Printf("WARN syslog: SIEM forwarding failing (reason=%q, %d consecutive lines lost) — events are NOT reaching the collector; the local audit log is unaffected; reconnecting every 5s",
			sanitizeLog(reason), consecutive)
	}
	// Evaluate immediately too: on a busy gateway the threshold is crossed by a
	// later failed line long before any timer would fire, and that is the
	// common case.
	evaluateSyslogEpisode()
}

// evaluateSyslogEpisode pages if the current failure episode has run past the
// degraded threshold and has not already paged.
//
// Reached from two places that must agree: the failure path (the common case —
// a busy gateway crosses the threshold on a later failed line) and the
// per-episode timer (the sparse case — a gateway that loses a line and then
// goes quiet). Both read syslogNow(), so a frozen test clock decides nothing
// however the real-clock timer fires.
func evaluateSyslogEpisode() {
	syslogHealth.mu.Lock()
	if syslogHealth.failingSince.IsZero() || syslogHealth.alerted {
		syslogHealth.mu.Unlock()
		return
	}
	failingFor := syslogNow().Sub(syslogHealth.failingSince)
	if failingFor < syslogDeliveryDegradedAfter {
		syslogHealth.mu.Unlock()
		return
	}
	syslogHealth.alerted = true
	reason := syslogHealth.lastReason
	stopSyslogAlertTimerLocked()
	syslogHealth.mu.Unlock()

	fireSyslogFailingAlert(fmt.Sprintf(
		"remote syslog/SIEM forwarding has been failing for over %s (reason: %s); audit and request events are not reaching the collector and are being discarded after the local write",
		syslogDeliveryDegradedAfter, reasonOrUnknown(reason)))
}

// noteSyslogDeliveryRecovered clears the episode on OBSERVED evidence — one
// line the collector socket accepted.
//
// Elapsed time never clears it. A feed that has stopped reporting failures
// because nothing is being logged looks identical to a healthy one, which is
// the mistake ca_health.go and storage_health.go both call out by name.
//
// Fenced on w for the same reason as the failure path: a stale recovery edge
// from a retired writer must not clear a real outage on the live one.
func noteSyslogDeliveryRecovered(w *syslogWriter) {
	syslogHealth.mu.Lock()
	if syslogHealth.owner != w {
		syslogHealth.mu.Unlock()
		return
	}
	wasFailing := !syslogHealth.failingSince.IsZero()
	suppressed := syslogHealth.suppressed
	syslogHealth.failingSince = time.Time{}
	syslogHealth.alerted = false
	syslogHealth.lastReason = ""
	syslogHealth.logAt = time.Time{}
	syslogHealth.suppressed = 0
	stopSyslogAlertTimerLocked()
	syslogHealth.mu.Unlock()

	if wasFailing && logger != nil {
		logger.Printf("syslog: SIEM forwarding recovered — the collector is accepting events again (%d suppressed failure log lines during the episode)", suppressed)
	}
}

// syslogSnapshot is the derived view every surface reads.
type syslogSnapshot struct {
	// Configured is operator INTENT: a target is set, whether or not it works.
	Configured bool
	// Connected is false when intent is set but no live Writer matches it —
	// the pre-existing "configured but failed to connect" state.
	Connected bool
	// Verifiable is false on UDP, where no counter this process keeps can
	// distinguish a healthy collector from one that does not exist.
	Verifiable bool
	// Degraded is true only when delivery has been failing continuously for
	// longer than syslogDeliveryDegradedAfter.
	Degraded bool
	// FailingFor is how long the current failure episode has run (0 = healthy).
	FailingFor          time.Duration
	Network             string
	Format              string
	Delivered           uint64
	Drops               uint64
	DropsCollectorDown  uint64
	DropsQueueFull      uint64
	DropsClosed         uint64
	DropsFlushTimeout   uint64
	Panics              uint64
	LastDelivery        time.Time
	ConsecutiveFailures int64
	LastFailureReason   string
}

// syslogState derives the current posture from the Writer's own health
// snapshot plus this file's episode anchor.
//
// It never takes the Writer's mutex — Health() is atomics only — so a scrape
// or a diagnostics read can never block behind a wedged collector. That is the
// same coupling Format() shed in this change.
func syslogState() syslogSnapshot {
	syslogHealth.mu.Lock()
	configured := syslogHealth.configured
	failingSince := syslogHealth.failingSince
	syslogHealth.mu.Unlock()

	// Intent is the authority for "is this feature in use": syslogConfiguredAddr
	// is recorded regardless of whether the dial succeeded, which is what lets
	// a silently-down feed be distinguished from an intentional no-op.
	snap := syslogSnapshot{Configured: configured || syslogConfiguredAddr != ""}
	if !snap.Configured {
		return snap
	}
	// Connected requires BOTH a live writer AND that the target it connected to
	// still matches current intent. A bare nil-check is not enough: observability
	// inits from YAML/flags BEFORE admin settings apply a persisted override, so
	// a later re-init that fails leaves globalSyslog non-nil pointing at the
	// PREVIOUS collector while intent has moved on.
	if globalSyslog == nil || syslogConfigured != syslogConfiguredAddr {
		return snap
	}
	snap.Connected = true

	h := globalSyslog.Health()
	snap.Verifiable = h.DeliveryVerifiable
	snap.Network = h.Network
	snap.Format = h.Format
	snap.Delivered = h.Delivered
	snap.Drops = h.Drops
	snap.DropsCollectorDown = h.DropsCollectorDown
	snap.DropsQueueFull = h.DropsQueueFull
	snap.DropsClosed = h.DropsClosed
	snap.DropsFlushTimeout = h.DropsFlushTimeout
	snap.Panics = h.Panics
	snap.LastDelivery = h.LastDelivery
	snap.ConsecutiveFailures = h.ConsecutiveFailures
	snap.LastFailureReason = h.LastFailureReason

	if !failingSince.IsZero() {
		snap.FailingFor = syslogNow().Sub(failingSince)
		// A negative age means the clock moved backwards under us (NTP step, VM
		// restore). Report the episode as just-started rather than as degraded:
		// the feed genuinely is failing, but paging on a clock correction is
		// noise and the next failure re-evaluates it honestly.
		if snap.FailingFor < 0 {
			snap.FailingFor = 0
		}
		snap.Degraded = snap.FailingFor >= syslogDeliveryDegradedAfter
	}
	return snap
}

// syslogWritePrometheus appends the culvert_syslog_* delivery series.
//
// Every series here is emitted ONLY when a SIEM target is configured. A
// `culvert_syslog_up 0` on an appliance that has never used SIEM forwarding is
// indistinguishable from one whose collector is dead, and the documented
// paging rule is `== 0` — so an unconditional gauge would page every
// deployment that does not use the feature. Same rule as the SOCKS5,
// cluster-CA, DNS and threat-feed gauges.
func syslogWritePrometheus(w *strings.Builder) {
	snap := syslogState()
	if !snap.Configured {
		return
	}

	w.WriteString("\n# HELP culvert_syslog_up 1 when a SIEM/syslog target is configured AND a live connection to it exists, 0 when the configured target failed to connect\n")
	w.WriteString("# TYPE culvert_syslog_up gauge\n")
	fmt.Fprintf(w, "culvert_syslog_up %d\n", boolGauge(snap.Connected))

	// The honest-coverage series. On UDP the process cannot observe delivery at
	// all, so an operator reading culvert_syslog_delivering must know whether a
	// green reading is evidence or merely the absence of evidence. This is the
	// OCSP-8 lesson applied to the SIEM plane: "found nothing wrong" and "never
	// checked" must not be the same scrape.
	w.WriteString("\n# HELP culvert_syslog_delivery_verifiable 1 when the transport can observe delivery failures (TCP), 0 when it cannot (UDP — writes to a blackholed collector succeed forever)\n")
	w.WriteString("# TYPE culvert_syslog_delivery_verifiable gauge\n")
	fmt.Fprintf(w, "culvert_syslog_delivery_verifiable %d\n", boolGauge(snap.Verifiable))

	// Deliberately emitted ONLY where it can mean something. On UDP a `1` here
	// would be a fiction and a `0` would be a false page; the verifiable gauge
	// above is what an operator alerts on for that transport.
	if snap.Verifiable {
		w.WriteString("\n# HELP culvert_syslog_delivering 1 when SIEM forwarding is delivering, 0 when it has been failing continuously past the degraded threshold\n")
		w.WriteString("# TYPE culvert_syslog_delivering gauge\n")
		fmt.Fprintf(w, "culvert_syslog_delivering %d\n", boolGauge(!snap.Degraded))
	}

	w.WriteString("\n# HELP culvert_syslog_delivered_total Log lines the SIEM collector socket accepted\n")
	w.WriteString("# TYPE culvert_syslog_delivered_total counter\n")
	fmt.Fprintf(w, "culvert_syslog_delivered_total %d\n", snap.Delivered)

	// Per-reason, because the remedies differ: collector_down is a network or
	// collector fault, queue_full says the collector is too SLOW for this
	// node's log rate, and panic is a code defect being contained.
	w.WriteString("\n# HELP culvert_syslog_drops_total Log lines lost before reaching the SIEM collector, by bounded reason class\n")
	w.WriteString("# TYPE culvert_syslog_drops_total counter\n")
	fmt.Fprintf(w, "culvert_syslog_drops_total{reason=\"collector_down\"} %d\n", snap.DropsCollectorDown)
	fmt.Fprintf(w, "culvert_syslog_drops_total{reason=\"queue_full\"} %d\n", snap.DropsQueueFull)
	fmt.Fprintf(w, "culvert_syslog_drops_total{reason=\"closed\"} %d\n", snap.DropsClosed)
	fmt.Fprintf(w, "culvert_syslog_drops_total{reason=\"flush_timeout\"} %d\n", snap.DropsFlushTimeout)
	fmt.Fprintf(w, "culvert_syslog_drops_total{reason=\"panic\"} %d\n", snap.Panics)

	w.WriteString("\n# HELP culvert_syslog_last_delivery_timestamp_seconds Unix time the SIEM collector last accepted a line (0 = never)\n")
	w.WriteString("# TYPE culvert_syslog_last_delivery_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_syslog_last_delivery_timestamp_seconds %d\n", unixOrZero(snap.LastDelivery))

	w.WriteString("\n# HELP culvert_syslog_consecutive_failures Collector-attributable line losses since the last successful delivery\n")
	w.WriteString("# TYPE culvert_syslog_consecutive_failures gauge\n")
	fmt.Fprintf(w, "culvert_syslog_consecutive_failures %d\n", snap.ConsecutiveFailures)
}
