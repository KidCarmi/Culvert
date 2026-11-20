package main

// alerts.go — package-main glue for webhook alert delivery, moved to
// internal/alerts (ADR-0002). The package started life as the producer seam
// (Payload / Sink / SetSink / Fire) and now also owns the delivery engine:
// the webhook Store, the Dispatch fan-out (per-store dedup + bounded
// concurrency), the SSRF-guarded HMAC-signed HTTP delivery, the persistent
// retry queue, and the RISK-003 secret encryption-at-rest. main keeps the
// process-wide singleton, the fireAlert wrapper every producer calls (also
// installed as the alerts.Fire sink), and the startup shim for the retry
// loop — the wrapper and the loop's store provider read alertStore() at
// call time, preserving the test-reassignment tolerance of the original.

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// Engine types re-exposed unqualified.
type (
	AlertWebhook  = alerts.Webhook
	AlertDelivery = alerts.Delivery
	AlertStore    = alerts.Store
	AlertPayload  = alerts.Payload
)

// alertStoreRef holds the process-wide alert store; read it through
// alertStore(). It is an atomic pointer rather than a plain variable because
// alert delivery runs on detached goroutines (`go fireAlert(...)`,
// `go alerts.Fire(...)` from a dozen producers) that read the store after the
// code that started them has returned. Production publishes the store once,
// but tests swap it, and a plain variable gave every such swap a data race
// with any alert goroutine left over from an earlier test (seen intermittently
// on the race lanes). Load/Store make the swap race-free; a goroutine that
// already loaded the old store simply finishes against it.
var alertStoreRef = func() *atomic.Pointer[AlertStore] {
	p := &atomic.Pointer[AlertStore]{}
	p.Store(&AlertStore{})
	return p
}()

// alertStore returns the current process-wide alert store.
func alertStore() *AlertStore { return alertStoreRef.Load() }

// fireAlert dispatches payload to all enabled webhooks matching event via the
// process-wide store. Installed as the alerts.Fire sink at init so internal
// packages (the scan engines) fire through the same path.
//
// It is a var so tests can observe the DISPATCH DECISION directly instead of
// asserting on webhook HTTP delivery. That distinction matters: delivery passes
// through a package-global concurrency semaphore in internal/alerts (cap 10)
// shared by every test in the binary, and when it is saturated Dispatch diverts
// the payload to the retry queue instead of delivering it. A delivery-based
// assertion therefore fails whenever unrelated tests happen to hold those slots
// — which is load- and order-dependent, and reports as "the alert was
// suppressed" even though the producer did everything right. Mirrors the same
// seam rationale as startupAlertFire below.
var fireAlert = func(event string, payload AlertPayload) {
	defer recoverGoroutine(crashComponentAlert) // fired via `go fireAlert(...)` from the proxy hot path
	alertStore().Dispatch(event, payload)
}

func init() {
	alerts.SetSink(fireAlert)
	// The subscription query behind the HasSubscriber gate that request-path
	// producers inside internal/* use (see alerts.HasSubscriber). Same
	// publish-once lifecycle as the sink; the probe reads the same
	// process-wide store the dispatch does.
	alerts.SetSubscriberProbe(func(event string) bool {
		return alertStore().HasSubscriber(event)
	})
}

// fireDNSFailureAlert reports a failed destination lookup from the proxy
// request path. It is the single producer for the "dns_failure" event, shared
// by the four per-request dial sites (plain HTTP, CONNECT bypass, CONNECT
// inspect, WebSocket) that previously each inlined the same payload literal.
//
// The HasSubscriber gate is load-bearing rather than cosmetic: this producer is
// driven by resolution failure, so its rate is set by the environment, not by
// the operator. A resolver outage or DGA-beaconing malware puts EVERY request on
// this path, and without the gate each one would spawn a delivery goroutine and
// format err.Error() to deliver an alert to nobody — the default posture is no
// webhooks configured. Gating keeps a DNS brownout from turning into goroutine
// churn on top of the outage. When a subscriber exists the dispatch is
// byte-identical to the previous inline call.
//
// CHAOS-64 bounded the Detail. It used to be the raw err.Error(), and
// Store.Dispatch dedups on `event + ":" + Detail`: a *net.DNSError's text
// embeds the QUERIED HOSTNAME and the resolver address, so every failure
// produced a DISTINCT dedup key that the 30 s window could not suppress by
// construction, and the fan-out landed in the 500-entry retry queue where it
// evicts REAL threat alerts. That is the WK-12/RS-5 defect, and here it is
// remotely triggerable: the hostname is chosen by the client, so any client
// could both fabricate unbounded alert volume and write arbitrary strings into
// an operator's alert pipeline. Detail now carries a bounded reason class; the
// full error is already logged at each of the four dial sites, so nothing is
// lost. Host stays as-is — it is a separate field and does not enter the dedup
// key, and knowing which destination failed is the point of the alert.
func fireDNSFailureAlert(host string, err error) {
	if !alertStore().HasSubscriber("dns_failure") {
		return
	}
	go fireAlert("dns_failure", AlertPayload{
		Host:   host,
		Detail: "destination lookup failed: " + classifyDNSFailure(err),
		Source: "proxy",
	})
}

// fireScanTimeoutAlert reports a fail-closed scan timeout from the two
// per-response scan sites (plain-HTTP inspect in proxy_http.go and the
// CONNECT-inspect leg in proxy_tunnel.go). It is the single producer for the
// "scan_timeout" event and applies the HasSubscriber contract
// fireDNSFailureAlert documents: this producer's rate is set by a FAULT (a
// saturated or dark scan engine), not by the operator.
//
// The gate matters more here than its rarity suggests. A timed-out scan writes
// a short cooldown memo (secscan.scanTimeoutCooldown) so that a hot object does
// not launch a stampede of doomed scans; every later request for that object
// inside the cooldown is answered from the memo WITHOUT scanning, and the memo
// still carries Source "timeout". Ungated, each of those requests paid a
// goroutine spawn, a payload build and a round trip through the alert store's
// dedup mutex to deliver an alert to nobody — the default posture is no
// webhooks configured — on the one node that is already degraded. When a
// subscriber exists the dispatch is byte-identical to the previous inline
// calls: same event, same payload fields, still detached.
func fireScanTimeoutAlert(actor, host, detail string) {
	if !alertStore().HasSubscriber("scan_timeout") {
		return
	}
	go fireAlert("scan_timeout", AlertPayload{
		Actor:  actor,
		Host:   host,
		Detail: detail,
		Source: "scan_timeout",
	})
}

// latchOncePerEpisodeOnDelivery is the fire-once-per-episode rule shared by
// the feed-freshness planes (threatfeed_health.go, blocklist_feed_health.go).
//
// The episode is consumed only by an alert that was DISPATCHED. Latching first
// and firing afterwards burned the episode whenever nothing subscribed — the
// DEFAULT posture, no webhooks configured — and these latches clear only on
// observed evidence (a clean sync) or a restart, never on elapsed time. So a
// node that went stale before any webhook existed spent its one page on nobody,
// and an operator who subscribed afterwards was never paged
// (SEC-BLFEED-STALE-LATCH-1, and the same shape in the threat-feed plane).
//
// mu must be the lock that guards *latched and *episode, and the caller must
// not hold it. The decision runs entirely under mu, so concurrent producers in
// one episode page at most once. delivered reports whether the alert was (or,
// for a queued startup alert, is about to be) dispatched to a subscriber; it
// runs under mu, so it must not block or take mu itself — the planes' sinks
// only probe the lock-free subscription index (HasSubscriber) and hand
// delivery to a goroutine.
//
// observed is the episode generation the caller read, under mu, BEFORE the
// feed state its staleness verdict came from. Every end of an episode (an
// observed recovery, a removal, a re-arm) bumps *episode under mu. The verdict
// is taken outside mu — reading it under mu would invert the lock order with
// the feed, whose observer takes mu — so a recovery can land between the
// verdict and this decision. Without the check, the recovery cleared the latch
// and this call set it straight back for an episode that had ended, and the
// NEXT episode could not page until another clean sync. A changed generation
// therefore skips without dispatching: the alert describes a condition already
// observed to have cleared. (A recovery that lands after this decision clears
// the latch itself, so either order ends correctly.)
//
// delivered is not called when the episode is already latched or has ended.
// It reports whether it SKIPPED for either reason.
func latchOncePerEpisodeOnDelivery(mu *sync.Mutex, latched *bool, episode *uint64, observed uint64, delivered func() bool) (skipped bool) {
	mu.Lock()
	defer mu.Unlock()
	if *latched || *episode != observed {
		return true
	}
	if delivered() {
		*latched = true
	}
	return false
}

// validateWebhookURL is re-exposed for the admin API handlers (config-time
// shape check; the SSRF check stays at delivery time).
var validateWebhookURL = alerts.ValidateURL

// validateWebhookEvents is re-exposed for the admin API handlers
// (SEC-ALERTS-EVENTNAME-1 shape check at ingress; see alerts.ValidateEventNames).
var validateWebhookEvents = alerts.ValidateEventNames

// maxAlertWebhooks is the store-wide webhook count limit (see
// alerts.MaxWebhooks), enforced by the API create arm and config import.
const maxAlertWebhooks = alerts.MaxWebhooks

// startAlertRetryLoop runs the F16 retry loop against the current
// process-wide store (resolved on every pass).
func startAlertRetryLoop(ctx context.Context) {
	alerts.StartRetryLoop(ctx, alertStore)
}

// ── Deferred startup alerts ──────────────────────────────────────────────────
//
// Alert webhooks load from disk in loadPersistentAdminState — the LAST
// startup slice — so an alert fired by an earlier init (e.g. the Root-CA
// load failure in loadRootCA, CHAOS-06) would fan out to an empty webhook
// list and vanish. deferStartupAlert queues such alerts until
// flushStartupAlerts runs after the webhook store is initialised; after the
// flush it degrades to a plain fireAlert passthrough.

// startupAlertFire is the flush/passthrough delivery sink — a seam so tests
// can observe delivery without a live webhook endpoint (mirrors the
// configSnapshotValidatorOK pattern).
var startupAlertFire = fireAlert

var (
	startupAlertMu      sync.Mutex
	startupAlertQueue   []queuedStartupAlert
	startupAlertFlushed bool
)

type queuedStartupAlert struct {
	event   string
	payload AlertPayload
	// stillValid, when set, is re-checked at the flush. A queued alert whose
	// condition has cleared since it was raised (its episode recovered before
	// the webhooks loaded) is DROPPED rather than delivered late as a false
	// page (Codex review of #1556). Nil means the alert reports a FACT that
	// stays true once it happened (a file was quarantined, a load failed at
	// boot) and is always delivered. A fire-once producer may also use it to
	// CLAIM its episode at the flush (claimThreatFeedStartupAlert): it is the
	// only point at which the webhook store is real, so it is the only point at
	// which "will this page reach a subscriber" has an answer. It then returns
	// false when its producer already paged the episode by another route, or
	// when the episode it was raised for has since recovered.
	stillValid func() bool
}

// deferStartupAlert fires event immediately when the startup flush has
// already happened, and queues it otherwise. Safe from any init order. For an
// alert about a condition that can RECOVER, use deferStartupAlertWhile.
func deferStartupAlert(event string, payload AlertPayload) {
	deferStartupAlertWhile(event, payload, nil)
}

// deferStartupAlertWhile is deferStartupAlert for a recoverable condition:
// if queued, the alert is delivered at the flush only while stillValid still
// reports the condition (typically: the same episode is still open). It is
// called without startupAlertMu held, so it may take the producer's own lock.
// After the flush the alert fires at once and stillValid is not consulted —
// the producer raised it about the present.
func deferStartupAlertWhile(event string, payload AlertPayload, stillValid func() bool) {
	startupAlertMu.Lock()
	if !startupAlertFlushed {
		startupAlertQueue = append(startupAlertQueue, queuedStartupAlert{event: event, payload: payload, stillValid: stillValid})
		startupAlertMu.Unlock()
		return
	}
	startupAlertMu.Unlock()
	startupAlertFire(event, payload)
}

// startupAlertsFlushed reports whether the startup flush has happened (the
// webhook store is loaded). Before it, a fire-once producer must queue through
// deferStartupAlert or its single page is lost to an empty webhook list.
func startupAlertsFlushed() bool {
	startupAlertMu.Lock()
	defer startupAlertMu.Unlock()
	return startupAlertFlushed
}

// flushStartupAlerts delivers every queued startup alert. Called once from
// loadPersistentAdminState after alertStore().Init has loaded the
// persisted webhooks.
func flushStartupAlerts() {
	startupAlertMu.Lock()
	queued := startupAlertQueue
	startupAlertQueue = nil
	startupAlertFlushed = true
	startupAlertMu.Unlock()
	for _, q := range queued {
		if q.stillValid != nil && !q.stillValid() {
			logger.Printf("Alerts: dropping queued startup alert %q — its condition cleared, or its producer already reported it, before the alert webhooks loaded", q.event)
			continue
		}
		startupAlertFire(q.event, q.payload)
	}
}
