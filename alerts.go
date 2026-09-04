package main

// alerts.go — package-main glue for webhook alert delivery, moved to
// internal/alerts (ADR-0002). The package started life as the producer seam
// (Payload / Sink / SetSink / Fire) and now also owns the delivery engine:
// the webhook Store, the Dispatch fan-out (per-store dedup + bounded
// concurrency), the SSRF-guarded HMAC-signed HTTP delivery, the persistent
// retry queue, and the RISK-003 secret encryption-at-rest. main keeps the
// process-wide singleton, the fireAlert wrapper every producer calls (also
// installed as the alerts.Fire sink), and the startup shim for the retry
// loop — the wrapper and the loop's store provider read globalAlertStore at
// call time, preserving the test-reassignment tolerance of the original.

import (
	"context"
	"sync"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// Engine types re-exposed unqualified.
type (
	AlertWebhook  = alerts.Webhook
	AlertDelivery = alerts.Delivery
	AlertStore    = alerts.Store
	AlertPayload  = alerts.Payload
)

// globalAlertStore is the process-wide webhook store.
var globalAlertStore = &AlertStore{}

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
	defer recoverGoroutine("alert") // fired via `go fireAlert(...)` from the proxy hot path
	globalAlertStore.Dispatch(event, payload)
}

func init() {
	alerts.SetSink(fireAlert)
	// The subscription query behind the HasSubscriber gate that request-path
	// producers inside internal/* use (see alerts.HasSubscriber). Same
	// publish-once lifecycle as the sink; the probe reads the same
	// process-wide store the dispatch does.
	alerts.SetSubscriberProbe(func(event string) bool {
		return globalAlertStore.HasSubscriber(event)
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
// CHAOS-57 bounded the Detail. It used to be the raw err.Error(), and
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
	if !globalAlertStore.HasSubscriber("dns_failure") {
		return
	}
	go fireAlert("dns_failure", AlertPayload{
		Host:   host,
		Detail: "destination lookup failed: " + classifyDNSFailure(nil, err),
		Source: "proxy",
	})
}

// validateWebhookURL is re-exposed for the admin API handlers (config-time
// shape check; the SSRF check stays at delivery time).
var validateWebhookURL = alerts.ValidateURL

// startAlertRetryLoop runs the F16 retry loop against the current
// process-wide store (resolved on every pass).
func startAlertRetryLoop(ctx context.Context) {
	alerts.StartRetryLoop(ctx, func() *alerts.Store { return globalAlertStore })
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
}

// deferStartupAlert fires event immediately when the startup flush has
// already happened, and queues it otherwise. Safe from any init order.
func deferStartupAlert(event string, payload AlertPayload) {
	startupAlertMu.Lock()
	if !startupAlertFlushed {
		startupAlertQueue = append(startupAlertQueue, queuedStartupAlert{event, payload})
		startupAlertMu.Unlock()
		return
	}
	startupAlertMu.Unlock()
	startupAlertFire(event, payload)
}

// flushStartupAlerts delivers every queued startup alert. Called once from
// loadPersistentAdminState after globalAlertStore.Init has loaded the
// persisted webhooks.
func flushStartupAlerts() {
	startupAlertMu.Lock()
	queued := startupAlertQueue
	startupAlertQueue = nil
	startupAlertFlushed = true
	startupAlertMu.Unlock()
	for _, q := range queued {
		startupAlertFire(q.event, q.payload)
	}
}
