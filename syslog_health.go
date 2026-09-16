package main

// syslog_health.go — CHAOS-66: the SIEM forwarding feed's delivery health.
//
// Why this file exists.
//
// `checkSyslogFeed` already answered one question — "did we ever connect?" —
// and answered it well. It did not answer the question that actually matters,
// which is "are events reaching the collector?", and the gap between the two is
// a complete silent failure:
//
//	drops=1  contract status=ok  message="remote syslog/SIEM forwarding is active"
//
// That line is from the reproduction against the real binary. The collector was
// gone — connection reset, listener closed — and every event was being dropped.
// The contract row, the `/api/syslog` readback and the GUI all reported an
// ACTIVE feed, because all three keyed on the same thing: a non-nil writer
// whose configured target matched operator intent. A writer stays non-nil
// forever once it has connected once; `internal/syslog`'s delivery state
// machine reconnects, fails, arms its 5 s backoff and drops, silently, for as
// long as the collector is away.
//
// The SIEM feed is a customer's compliance and forensic record (CWE-778,
// OWASP A09:2021). "The collector is unreachable" and "nothing has happened"
// are the same picture from the collector's side, so a dark feed is
// indistinguishable from a quiet network — which is exactly the state an
// attacker who has disrupted log forwarding wants the console to show. The
// sibling defect on the DP→CP audit push queue was closed by CHAOS-61 (silent
// drops, now `culvert_audit_cluster_push_drops_total`); this is the same class
// on the EXTERNAL feed, which is the one an auditor reads.
//
// The plane is built on EVIDENCE, not on inference:
//
//   - Health is driven by `internal/syslog`'s delivery observer, which reports
//     the outcome of every delivery attempt from the drain goroutine. A
//     DELIVERED line is the only thing that clears a degraded feed; elapsed
//     time never does (the ca_health.go / storage_health.go house rule — a
//     feed that stopped failing because it stopped being written to has not
//     recovered).
//
//   - Degradation is a DURATION, not a count. The engine's reconnect backoff is
//     5 s, a SIEM failover or a collector restart clears in seconds, and a
//     gateway emits one line per proxied request — so a count-based threshold
//     would page on every ordinary collector restart on a busy node, and would
//     be trivially reachable by traffic volume rather than by fault severity.
//
//   - A node with NO traffic produces no evidence, and this plane does not
//     invent any. It reports what it has observed and publishes
//     `culvert_syslog_last_success_timestamp_seconds` so an operator can alert
//     on staleness over a window of their choosing. The complementary case —
//     a feed that has NEVER connected — is covered by the reconnect campaign
//     in syslog_recovery.go, which produces its own evidence by attempting.
//
// Surfaces, all reusing existing operator vocabulary:
//
//   - `/api/diagnostics` — the existing `syslog_feed` contract row, which now
//     has a degraded verdict instead of only "connected / not connected".
//   - `/health` — the `siem_feed` posture field (fixed enum; unauthenticated).
//   - `/metrics` — culvert_syslog_{up,delivered_total,drops_total,
//     queue_drops_total,panics_total,degraded,last_success_timestamp_seconds}.
//   - alerts — `siem_feed_down`, fired once per episode.
//
// Deliberately NOT added, and recorded rather than silently omitted:
//
//   - No `/readyz` row. A node whose SIEM feed is down is proxying traffic
//     perfectly and enforcing every policy; failing readiness would eject a
//     healthy gateway from the load balancer over its logging pipeline —
//     the trade §19 refused for the category store and §25 refused for the
//     admin UI, refused again here for the same reason.
//   - No fail-closed option. Refusing to proxy because a third-party collector
//     is unreachable converts the SIEM's outage into the customer's. Same
//     asymmetry CHAOS-59 records for the threat feed.
//   - Nothing for UDP. A UDP "connection" never fails, so every line is
//     reported delivered whether or not a collector exists. That is a property
//     of the transport, not of this code, and it is stated in the runbook so an
//     operator who needs delivery evidence chooses TCP.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// syslogFeedDegradedAfter is how long delivery must fail CONTINUOUSLY
	// before the feed is reported degraded (fail row, alert, gauge).
	//
	// A duration rather than a count, for the reason in the header: the drain
	// goroutine retries on a 5 s backoff and a gateway generates one line per
	// proxied request, so a count threshold measures traffic volume rather than
	// fault severity and would fire on every collector restart of a busy node.
	// Sixty seconds of a SIEM feed delivering nothing is no longer a failover.
	syslogFeedDegradedAfter = 60 * time.Second

	// syslogFeedLogInterval rate-limits the delivery-failure log line: the
	// FIRST failure of an episode is logged immediately (the operator must see
	// the onset), then at most one line per interval, then one recovery line
	// naming the count the gate suppressed. The same discipline as
	// storage_health.go and socks5_health.go — the log carries the SIGNAL, the
	// counter carries the MAGNITUDE. A mitigation for a log-loss defect must
	// not be a log-flood defect.
	syslogFeedLogInterval = 5 * time.Minute
)

// syslogFeedHealth is the process-wide record of the SIEM feed's delivery
// state. The cumulative counters are atomics so the healthy path costs no
// mutex at all (the delivery observer runs once per forwarded line); the
// EPISODE state is mutex-guarded because every reader — the contract row, the
// health field, the metrics block — needs a consistent view across all of it.
type syslogFeedHealth struct {
	mu sync.Mutex

	// configured records operator INTENT: a syslog target was asked for. It is
	// what gates metric emission, for the socks5/cluster_ca reason — `up 0` on
	// an appliance that never configured a SIEM is indistinguishable from a
	// dead feed, and the documented paging rule is `== 0`.
	configured bool

	// connected is true while a Writer is published. It is NOT health: a
	// connected writer that delivers nothing is the whole finding.
	connected bool

	// firstFailure opens the current run of consecutive failures; zero while
	// delivering. Degradation is measured from here, so a feed that fails,
	// delivers, and fails again never accumulates toward the threshold across
	// healthy periods.
	firstFailure time.Time
	lastFailure  time.Time
	lastSuccess  time.Time

	// consecutive resets on an OBSERVED delivery; it is the only thing that
	// does. everDelivered separates the two operator situations a gauge cannot
	// distinguish: a feed that has never once delivered (a misconfigured
	// target, a firewall that was never opened) from one that was working and
	// stopped (an environmental fault).
	consecutive   int64
	everDelivered bool

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per DEGRADATION episode: one page when the
	// feed goes persistently dark, never one per dropped line. Cleared by an
	// observed delivery, so a second incident pages again.
	alerted bool
}

var syslogFeed syslogFeedHealth

// Cumulative counters, kept OUT of the mutex so a healthy delivery costs two
// atomic adds rather than a lock acquisition. They are monotonic totals, never
// episode state, so they need no consistency with the fields above.
var (
	syslogDeliveredTotal atomic.Int64
	syslogFailedTotal    atomic.Int64

	// syslogFeedFailing short-circuits the success observer while nothing is
	// wrong: a delivery on a healthy feed takes no lock (the storageEverFailed
	// pattern). Set while an episode is open, cleared by the delivery that
	// closes it.
	syslogFeedFailing atomic.Bool
)

// fireSyslogFeedAlert delivers the `siem_feed_down` alert.
//
// Package-level seam so tests observe the transition SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
var fireSyslogFeedAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("siem_feed_down") {
		return
	}
	go fireAlert("siem_feed_down", AlertPayload{
		Detail: detail,
		Source: "syslog",
	})
}

// noteSyslogConfigured records that a SIEM target was requested. Called from
// every path that records operator intent — both startup loaders and the admin
// API — BEFORE the first connect attempt, so a feed that fails on its very
// first attempt is reported against a CONFIGURED service rather than as "no
// SIEM" (the CHAOS-54 ordering rule).
func noteSyslogConfigured() {
	syslogFeed.mu.Lock()
	syslogFeed.configured = true
	syslogFeed.mu.Unlock()
}

// noteSyslogConnected records that a Writer was successfully published. It
// deliberately does NOT clear a degradation: connecting is not delivering, and
// treating a successful dial as recovery is the exact inference this file
// exists to remove. Only noteSyslogDelivery(true) clears.
func noteSyslogConnected() {
	syslogFeed.mu.Lock()
	syslogFeed.configured = true
	syslogFeed.connected = true
	syslogFeed.mu.Unlock()
}

// noteSyslogDisabled records that forwarding was switched off by an operator.
// That is not a fault: a disabled feed must not report as degraded and must not
// alert, so the episode is cleared rather than left latched.
func noteSyslogDisabled() {
	syslogFeed.mu.Lock()
	syslogFeed.configured = false
	syslogFeed.connected = false
	syslogFeed.firstFailure = time.Time{}
	syslogFeed.consecutive = 0
	syslogFeed.alerted = false
	syslogFeed.logAt = time.Time{}
	syslogFeed.suppressed = 0
	syslogFeed.mu.Unlock()
	syslogFeedFailing.Store(false)
}

// noteSyslogDelivery is the delivery observer wired into every Writer this
// process constructs (newSyslogWriter). It runs on the engine's drain
// goroutine, once per delivery ATTEMPT — never on a request goroutine.
func noteSyslogDelivery(delivered bool) {
	if delivered {
		syslogDeliveredTotal.Add(1)
		// Fast path: nothing is wrong and nothing was wrong, so there is no
		// episode to close and no lock to take.
		if !syslogFeedFailing.Load() {
			syslogFeed.mu.Lock()
			syslogFeed.lastSuccess = time.Now()
			syslogFeed.everDelivered = true
			syslogFeed.mu.Unlock()
			return
		}
		noteSyslogRecovered(time.Now())
		return
	}
	syslogFailedTotal.Add(1)
	noteSyslogFailure(time.Now())
}

// noteSyslogFailure records one failed delivery and emits the rate-limited log
// line and the fire-once alert when they are due.
func noteSyslogFailure(now time.Time) {
	syslogFeedFailing.Store(true)

	syslogFeed.mu.Lock()
	syslogFeed.consecutive++
	syslogFeed.lastFailure = now
	if syslogFeed.firstFailure.IsZero() {
		syslogFeed.firstFailure = now
	}

	shouldLog := false
	if syslogFeed.logAt.IsZero() || now.Sub(syslogFeed.logAt) >= syslogFeedLogInterval {
		syslogFeed.logAt = now
		shouldLog = true
	} else {
		syslogFeed.suppressed++
	}

	degraded := now.Sub(syslogFeed.firstFailure) >= syslogFeedDegradedAfter
	alertNow := degraded && !syslogFeed.alerted
	if alertNow {
		syslogFeed.alerted = true
	}
	consecutive := syslogFeed.consecutive
	darkFor := now.Sub(syslogFeed.firstFailure)
	everDelivered := syslogFeed.everDelivered
	syslogFeed.mu.Unlock()

	if shouldLog {
		logger.Printf("WARN SIEM_FEED_DOWN: remote syslog delivery is failing (%d consecutive, %s) — events are NOT reaching the collector and are being dropped",
			consecutive, darkFor.Round(time.Second))
	}
	if alertNow {
		posture := "has never delivered an event since this node started"
		if everDelivered {
			posture = "has stopped delivering events"
		}
		// BOUNDED detail, never the transport error: Dispatch dedups on
		// event+Detail, and a transport error embeds the collector address and
		// the ephemeral local port, which would mint one dedup key per failure
		// and evict real threat alerts from the retry queue (WK-12/RS-5).
		fireSyslogFeedAlert(fmt.Sprintf(
			"Remote syslog/SIEM forwarding %s for over %s (%d consecutive failed deliveries); audit and request events are being DROPPED and will not appear in the collector. The proxy data plane is UNAFFECTED and still enforcing policy; this node's local audit log and request log are unaffected.",
			posture, syslogFeedDegradedAfter, consecutive))
	}
}

// noteSyslogRecovered closes an episode on OBSERVED evidence — a line that
// actually reached the collector. Elapsed time never closes one: a feed that
// has stopped failing because nothing is being written to it looks identical
// to a healthy one, which is the mistake ca_health.go and storage_health.go
// both call out by name.
func noteSyslogRecovered(now time.Time) {
	syslogFeed.mu.Lock()
	syslogFeed.lastSuccess = now
	syslogFeed.everDelivered = true
	consecutive := syslogFeed.consecutive
	suppressed := syslogFeed.suppressed
	darkFor := time.Duration(0)
	if !syslogFeed.firstFailure.IsZero() {
		darkFor = now.Sub(syslogFeed.firstFailure)
	}
	syslogFeed.consecutive = 0
	syslogFeed.suppressed = 0
	syslogFeed.firstFailure = time.Time{}
	syslogFeed.alerted = false
	syslogFeed.logAt = time.Time{}
	syslogFeed.mu.Unlock()
	syslogFeedFailing.Store(false)

	if consecutive > 0 {
		logger.Printf("SIEM_FEED_RECOVERED: remote syslog delivery restored after %s (%d events dropped during the outage, %d log lines suppressed)",
			darkFor.Round(time.Second), consecutive, suppressed)
	}
}

// syslogFeedSnapshot is the consistent view handed to the reporting surfaces.
type syslogFeedSnapshot struct {
	Configured    bool
	Connected     bool
	Degraded      bool
	Failing       bool
	EverDelivered bool
	Consecutive   int64
	Delivered     int64
	Failed        int64
	DarkFor       time.Duration
	LastSuccess   time.Time
	// Reconnecting is true while the recovery campaign (syslog_recovery.go) is
	// dialling a collector this node has never managed to reach. It changes the
	// operator ACTION — "wait, it retries" rather than "re-save the target" —
	// which is why the contract row carries it.
	Reconnecting      bool
	ReconnectAttempts int64
	// Drops/QueueDrops/Panics come from the live Writer and are zero when none
	// is published.
	Drops      uint64
	QueueDrops uint64
	Panics     uint64
}

// syslogFeedState returns a consistent copy of the feed's health.
func syslogFeedState() syslogFeedSnapshot {
	syslogFeed.mu.Lock()
	snap := syslogFeedSnapshot{
		Configured:    syslogFeed.configured,
		Connected:     syslogFeed.connected,
		EverDelivered: syslogFeed.everDelivered,
		Consecutive:   syslogFeed.consecutive,
		LastSuccess:   syslogFeed.lastSuccess,
	}
	if !syslogFeed.firstFailure.IsZero() {
		snap.Failing = true
		snap.DarkFor = syslogFeed.lastFailure.Sub(syslogFeed.firstFailure)
		snap.Degraded = snap.DarkFor >= syslogFeedDegradedAfter
	}
	syslogFeed.mu.Unlock()

	snap.Delivered = syslogDeliveredTotal.Load()
	snap.Failed = syslogFailedTotal.Load()
	snap.Reconnecting, snap.ReconnectAttempts = syslogReconnectActive()
	if sw := activeSyslog(); sw != nil {
		snap.Drops = sw.Drops()
		snap.QueueDrops = sw.QueueDrops()
		snap.Panics = sw.Panics()
	}
	return snap
}

// syslogActiveFormat reports the wire format of the active writer, or the
// default when none is published. Keeps the admin API off a nil deref now that
// publication is atomic and a concurrent disable can land between two reads.
func syslogActiveFormat() string {
	if sw := activeSyslog(); sw != nil {
		return sw.Format()
	}
	return "rfc3164"
}

// syslogFeedStatus is the /health posture string for the SIEM feed.
//
// A fixed five-value enum, deliberately, because handleHealth serves this
// UNAUTHENTICATED on the proxy port. What stays off the public surface is the
// RESOLUTION — the collector address, the failure count, the drop totals — all
// of which live on the role-gated /api/diagnostics row, the alert and the logs.
func syslogFeedStatus() string {
	snap := syslogFeedState()
	switch {
	case !snap.Configured:
		return "disabled"
	case snap.Degraded:
		return "down"
	case snap.Failing:
		return "degraded"
	case !snap.Connected:
		return "connecting"
	default:
		return "ready"
	}
}

// resetSyslogFeedHealthForTest clears the record. Test isolation only.
//
// Fields are zeroed individually rather than by assigning a fresh struct: the
// mutex is a FIELD of the record, so `syslogFeed = syslogFeedHealth{}` under
// the lock replaces the held mutex with an unlocked zero value and the
// following Unlock is a fatal "unlock of unlocked mutex" (the CHAOS-54 note).
func resetSyslogFeedHealthForTest() {
	syslogFeed.mu.Lock()
	syslogFeed.configured = false
	syslogFeed.connected = false
	syslogFeed.firstFailure = time.Time{}
	syslogFeed.lastFailure = time.Time{}
	syslogFeed.lastSuccess = time.Time{}
	syslogFeed.consecutive = 0
	syslogFeed.everDelivered = false
	syslogFeed.logAt = time.Time{}
	syslogFeed.suppressed = 0
	syslogFeed.alerted = false
	syslogFeed.mu.Unlock()
	syslogFeedFailing.Store(false)
	syslogDeliveredTotal.Store(0)
	syslogFailedTotal.Store(0)
}

// syslogWritePrometheus emits the SIEM feed series.
//
// Emitted ONLY when a SIEM target is configured — the socks5/cluster_ca/dns
// rule. A flat block of zeros from every appliance that never configured a
// collector is indistinguishable from one whose feed is dead, and the
// documented paging rule here is `culvert_syslog_up == 0`.
//
// Every value is a plain total, a 0/1 gauge or a timestamp: /metrics is
// unauthenticated on the proxy port, so no collector address, hostname or
// error text may appear, and nothing here is a label.
func syslogWritePrometheus(w interface{ Write([]byte) (int, error) }) {
	snap := syslogFeedState()
	if !snap.Configured {
		return
	}
	up, degraded := 1, 0
	if snap.Failing {
		up = 0
	}
	if snap.Degraded {
		degraded = 1
	}
	var lastSuccess float64
	if !snap.LastSuccess.IsZero() {
		lastSuccess = float64(snap.LastSuccess.Unix())
	}
	reconnecting := 0
	if snap.Reconnecting {
		reconnecting = 1
		// A feed that has never connected is not "up" either, whatever the
		// delivery observer has seen (which on that path is nothing at all).
		up = 0
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_syslog_up 1 while remote syslog delivery is succeeding; 0 while deliveries are failing
# TYPE culvert_syslog_up gauge
culvert_syslog_up %d

# HELP culvert_syslog_degraded 1 while remote syslog delivery has been failing for longer than the degradation threshold
# TYPE culvert_syslog_degraded gauge
culvert_syslog_degraded %d

# HELP culvert_syslog_delivered_total Log lines that reached the remote syslog/SIEM collector since startup
# TYPE culvert_syslog_delivered_total counter
culvert_syslog_delivered_total %d

# HELP culvert_syslog_drops_total Log lines that never reached the collector since startup (all causes)
# TYPE culvert_syslog_drops_total counter
culvert_syslog_drops_total %d

# HELP culvert_syslog_queue_drops_total Subset of dropped lines lost to delivery-queue overflow rather than an unreachable collector
# TYPE culvert_syslog_queue_drops_total counter
culvert_syslog_queue_drops_total %d

# HELP culvert_syslog_panics_total Log lines lost to a recovered panic in the syslog delivery goroutine
# TYPE culvert_syslog_panics_total counter
culvert_syslog_panics_total %d

# HELP culvert_syslog_last_success_timestamp_seconds Unix time of the last line that reached the collector; 0 if none has
# TYPE culvert_syslog_last_success_timestamp_seconds gauge
culvert_syslog_last_success_timestamp_seconds %g

# HELP culvert_syslog_reconnecting 1 while the forwarder is retrying a collector it has never managed to reach
# TYPE culvert_syslog_reconnecting gauge
culvert_syslog_reconnecting %d

# HELP culvert_syslog_reconnect_attempts_total Reconnect attempts made by the startup-failure recovery campaign
# TYPE culvert_syslog_reconnect_attempts_total counter
culvert_syslog_reconnect_attempts_total %d
`,
		up,
		degraded,
		snap.Delivered,
		snap.Drops,
		snap.QueueDrops,
		snap.Panics,
		lastSuccess,
		reconnecting,
		snap.ReconnectAttempts,
	)
}
