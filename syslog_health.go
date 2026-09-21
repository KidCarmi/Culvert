package main

// syslog_health.go — CHAOS-66: the SIEM forwarding path's health plane.
//
// Why this file exists.
//
// `internal/syslog` is the CENTRALIZED half of this appliance's compliance
// record: `store.go` forwards every audit entry and every request-log entry to
// it, and on a fleet it is the copy a SOC actually reads. The engine itself is
// carefully built — bounded queue, single drain goroutine, write deadlines,
// panic containment, a reconnect state machine — and it counts every line it
// loses in `Drops()`. What was missing is everything ABOVE the counter.
//
// Before this change, `Drops()` reached exactly ONE surface in the whole
// process: `GET /api/syslog`, an admin-only JSON endpoint. There was no
// metric, no `/healthz` field, no operator-contract verdict that consulted it,
// no alert and no log line. A SIEM outage was therefore invisible to every
// automated monitor the product ships, which is the same CWE-778 / A09:2021
// shape this register has now closed twice on either side of it — §13 for the
// local audit JSONL (`culvert_audit_write_errors_total` + `/healthz` + the
// `storage_write_failed` alert) and §30 for the DP→CP audit push queue
// (`culvert_audit_cluster_push_drops_total`). A 2026-07-07 security review
// (`docs/security-reviews/2026-07-07-secret-containment-maint-agent-chaos-window.md`)
// recommended `culvert_syslog_dropped_total` by name; it was never built.
//
// Worse than absent: the one surface that did claim to report on this feed
// answered the wrong question. `checkSyslogFeed` returned
//
//	"remote syslog/SIEM forwarding is active"
//
// whenever a writer existed and its target matched operator intent — i.e. it
// reported whether the process CONNECTED ONCE AT STARTUP, never whether the
// collector is receiving. Measured against the real code path: with the
// collector killed and 200 audit events forwarded, `Drops()` reached 200 and
// the row still read `ok` / "active". The row's own doc comment argues that a
// bare `globalSyslog != nil` check is not enough, and then reasons only about
// the intent-vs-target axis; the delivery axis was never considered. A
// collector that goes away mid-life is far more likely than one that is down
// at exactly the instant of boot, so the row was green for the common case and
// red only for the rare one.
//
// And the DEFAULT transport cannot answer the question at all. `udp://` is
// what an address with no scheme resolves to, a connected UDP socket's write
// succeeds locally whether or not anything is listening, so on a UDP feed
// `Drops()` is 0, delivery state is up and every surface reports a healthy
// SIEM feed against a collector that does not exist. That is a protocol fact,
// not a bug to fix — so the surfaces stop claiming delivery they cannot
// observe, and say which posture the operator is in (see
// `(*syslog.Writer).DeliveryVerifiable`).
//
// What this plane does, borrowing its mechanism from `socks5_health.go` and
// `admin_ui_health.go` rather than inventing a second dialect:
//
//   - counts everything, and reports recovery on OBSERVED evidence only (a
//     line that actually reached the collector) — never on elapsed time;
//   - treats degradation as a DURATION (`syslogFeedDegradedAfter`), not a
//     count, so a SIEM restart or a brief network blip does not page;
//   - logs onset immediately, then at most one line per
//     `syslogFeedLogInterval`, then one recovery line naming the suppressed
//     count — signal in the log, magnitude in the counter;
//   - fires `siem_feed_down` ONCE per episode, `HasSubscriber`-gated, with a
//     BOUNDED reason class in the Detail (`Dispatch` dedups on
//     `event + ":" + Detail`, and a raw net error embeds the collector address
//     and the ephemeral local port — the WK-12/RS-5 defect);
//   - emits its metrics ONLY when a SIEM target is configured, because
//     `culvert_syslog_up 0` on an appliance that never had a SIEM is
//     indistinguishable from one whose feed is dead, and the documented
//     paging rule is `== 0` (the socks5 / cluster_ca / dns rule).
//
// Deliberately NOT on `/readyz`, and that is load-bearing: a node whose SIEM
// feed is down is proxying perfectly and enforcing every policy. Failing
// readiness would eject a healthy gateway from the load balancer over its
// logging pipeline, converting an observability outage into the traffic
// outage this plane exists to make visible — the same trade §19 refused for
// the category store and §25 refused for the admin UI listener.
//
// The alert event name is NEW rather than reused. The register's rule is not
// "never mint a name", it is "never mint a SECOND name for one root cause"
// (§19 reused `state_file_corrupt`, §28 reused `dns_failure`, §17 reused
// `cert_expiry`). A collector the appliance cannot reach shares no root cause
// and no operator action with a failing disk or a stale feed, so it gets its
// own name, exactly as `socks5_listener_down` (§22) and `admin_ui_unavailable`
// (§25) did. `HasSubscriber` honours the `"*"` catch-all, so a wildcard
// subscriber receives it without reconfiguration.

import (
	"sync"
	"sync/atomic"
	"time"
)

// syslogFeedDegradedAfter is how long delivery must be failing before the feed
// is reported DEGRADED and the alert fires.
//
// A DURATION rather than a count, for the reason `admin_ui_health.go` and
// `dns_health.go` record: the entry rate of a busy gateway is thousands of
// lines a minute, so any count threshold is reached inside a SIEM's ordinary
// restart window and would page on every collector redeploy. Sixty seconds is
// longer than a container restart and far shorter than a compliance gap an
// operator would want to learn about from an auditor.
const syslogFeedDegradedAfter = 60 * time.Second

// syslogFeedLogInterval rate-limits the degraded log line. A mitigation for a
// write-amplification defect must not be one itself: the drain goroutine
// re-enters the observer once per dropped line, and this feed's whole purpose
// is carrying one line per proxied request.
const syslogFeedLogInterval = 60 * time.Second

// syslogProbeBudget bounds one operator-triggered connectivity probe end to
// end (dial + write). Deliberately the same order as the engine's own
// writeTimeout: a connectivity check must not park an admin request longer
// than one ordinary delivery attempt would.
const syslogProbeBudget = 5 * time.Second

// syslogFeedDown is the fast-path gate. Steady-state healthy delivery costs
// the drain goroutine two atomic loads and returns before any mutex.
var syslogFeedDown atomic.Bool

// syslogFeed is the process-wide delivery-state record.
var syslogFeed struct {
	mu sync.Mutex

	everDelivered bool      // a line has reached the collector at least once
	firstFailure  time.Time // start of the current failing episode
	lastFailure   time.Time
	lastRecovery  time.Time
	lastReason    string
	consecutive   int64
	episodes      int64
	recoveries    int64
	degraded      bool
	alerted       bool // fire-once-per-episode latch
	logAt         time.Time
	suppressed    int64
}

// fireSyslogFeedAlert delivers the `siem_feed_down` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the
// default posture, and the state of every test binary — this must not spawn a
// goroutine at all.
var fireSyslogFeedAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("siem_feed_down") {
		return
	}
	go fireAlert("siem_feed_down", AlertPayload{
		Detail: detail,
		Source: "syslog",
	})
}

// noteSyslogDeliveryState is the Writer's state observer (wired by
// wireSyslogObservers). It runs on the drain goroutine, once per delivery
// outcome, with the Writer's mutex released.
func noteSyslogDeliveryState(sw *syslogWriter, up bool, reason string, changed bool) {
	if up && !changed && !syslogFeedDown.Load() {
		return // healthy steady state
	}
	now := time.Now()
	if up {
		noteSyslogDeliveryRecovered(now)
		return
	}
	noteSyslogDeliveryFailed(sw, reason, now)
}

// noteSyslogDeliveryFailed records one failed delivery and decides, under the
// rate gate, whether to log and whether to page.
func noteSyslogDeliveryFailed(sw *syslogWriter, reason string, now time.Time) {
	syslogFeedDown.Store(true)

	syslogFeed.mu.Lock()
	if syslogFeed.firstFailure.IsZero() {
		syslogFeed.firstFailure = now
		syslogFeed.episodes++
	}
	syslogFeed.lastFailure = now
	syslogFeed.lastReason = reason
	syslogFeed.consecutive++

	shouldLog := false
	if syslogFeed.logAt.IsZero() || now.Sub(syslogFeed.logAt) >= syslogFeedLogInterval {
		syslogFeed.logAt = now
		shouldLog = true
	} else {
		syslogFeed.suppressed++
	}

	degraded := now.Sub(syslogFeed.firstFailure) >= syslogFeedDegradedAfter
	syslogFeed.degraded = degraded
	alertNow := degraded && !syslogFeed.alerted
	if alertNow {
		syslogFeed.alerted = true
	}
	failingFor := now.Sub(syslogFeed.firstFailure)
	syslogFeed.mu.Unlock()

	if shouldLog {
		// The CAUSE (which embeds the collector address and the ephemeral local
		// port) goes here and nowhere else — never to the alert Detail, never
		// to the viewer-role contract row.
		logger.Printf("WARN syslog: SIEM delivery failing (reason=%q, for=%s, dropped=%d, cause=%q) — audit and request-log entries are not reaching the collector",
			sanitizeLog(reason), failingFor.Round(time.Second), sw.Drops(), sanitizeLog(sw.LastCause()))
	}
	if alertNow {
		fireSyslogFeedAlert(reason)
	}
}

// noteSyslogDeliveryRecovered clears the episode on OBSERVED evidence: a line
// that actually reached the collector. Elapsed time never clears it — a feed
// that stopped failing because nothing is being written looks identical to a
// delivering one (the ca_health.go / storage_health.go discipline).
func noteSyslogDeliveryRecovered(now time.Time) {
	syslogFeedDown.Store(false)

	syslogFeed.mu.Lock()
	syslogFeed.everDelivered = true
	wasFailing := !syslogFeed.firstFailure.IsZero()
	failedFor := time.Duration(0)
	if wasFailing {
		failedFor = now.Sub(syslogFeed.firstFailure)
	}
	suppressed := syslogFeed.suppressed
	syslogFeed.firstFailure = time.Time{}
	syslogFeed.consecutive = 0
	syslogFeed.degraded = false
	syslogFeed.alerted = false
	syslogFeed.logAt = time.Time{}
	syslogFeed.suppressed = 0
	if wasFailing {
		syslogFeed.recoveries++
		syslogFeed.lastRecovery = now
	}
	syslogFeed.mu.Unlock()

	if wasFailing {
		logger.Printf("Syslog: SIEM delivery recovered after %s (%d further failure log lines suppressed)",
			failedFor.Round(time.Second), suppressed)
	}
}

// syslogFeedSnapshot is the lock-free view handed to the reporting surfaces.
type syslogFeedSnapshot struct {
	Configured         bool
	Intent             string // operator-configured target (may differ from Target on a failed reconfigure)
	Target             string // what the live writer is aimed at
	Transport          string // "udp" or "tcp"
	DeliveryVerifiable bool   // false for UDP — see (*syslog.Writer).DeliveryVerifiable
	Installed          bool   // a writer exists
	Up                 bool   // last OBSERVED delivery outcome
	EverDelivered      bool
	Degraded           bool
	FailingFor         time.Duration
	LastReason         string
	Drops              uint64
	QueueDrops         uint64
	Panics             uint64
	Episodes           int64
	Recoveries         int64
}

// syslogFeedState reports the live SIEM-feed posture.
func syslogFeedState() syslogFeedSnapshot {
	snap := syslogFeedSnapshot{
		Intent:     syslogConfiguredAddr,
		Configured: syslogConfiguredAddr != "",
	}
	sw := activeSyslog()
	if sw != nil {
		snap.Installed = true
		snap.Target = sw.Target()
		snap.Transport = sw.Network()
		snap.DeliveryVerifiable = sw.DeliveryVerifiable()
		snap.Up = sw.Up()
		snap.Drops = sw.Drops()
		snap.QueueDrops = sw.QueueDrops()
		snap.Panics = sw.Panics()
	}

	syslogFeed.mu.Lock()
	snap.EverDelivered = syslogFeed.everDelivered
	snap.Degraded = syslogFeed.degraded
	snap.LastReason = syslogFeed.lastReason
	snap.Episodes = syslogFeed.episodes
	snap.Recoveries = syslogFeed.recoveries
	if !syslogFeed.firstFailure.IsZero() {
		snap.FailingFor = time.Since(syslogFeed.firstFailure)
		// Degradation is EVALUATED here as well as on the delivery path, so a
		// feed that went down and then saw no further traffic still reports
		// the truth to a scrape. The ALERT is deliberately not fired from a
		// read path: a surface nobody scrapes must not decide whether an
		// operator is paged.
		if snap.FailingFor >= syslogFeedDegradedAfter {
			snap.Degraded = true
		}
	}
	syslogFeed.mu.Unlock()
	return snap
}

// resetSyslogFeedHealth clears the process-global delivery record, starting a
// fresh episode.
//
// This is a PRODUCTION operation, not just a test hook: installing a new
// forwarder (or disabling forwarding) ends the previous writer's episode, and
// carrying its degradation state onto a different collector would report the
// old target's outage against the new one. Tests reuse it to stop these
// globals leaking across cases under -count/-shuffle, the way
// resetAuthBackendHealthForTest does — hence no ForTest suffix, which would
// have been a lie at two of its three call sites.
func resetSyslogFeedHealth() {
	syslogFeedDown.Store(false)
	syslogFeed.mu.Lock()
	syslogFeed.everDelivered = false
	syslogFeed.firstFailure = time.Time{}
	syslogFeed.lastFailure = time.Time{}
	syslogFeed.lastRecovery = time.Time{}
	syslogFeed.lastReason = ""
	syslogFeed.consecutive = 0
	syslogFeed.episodes = 0
	syslogFeed.recoveries = 0
	syslogFeed.degraded = false
	syslogFeed.alerted = false
	syslogFeed.logAt = time.Time{}
	syslogFeed.suppressed = 0
	syslogFeed.mu.Unlock()
}
