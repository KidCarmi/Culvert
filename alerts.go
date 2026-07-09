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
func fireAlert(event string, payload AlertPayload) {
	globalAlertStore.Dispatch(event, payload)
}

func init() { alerts.SetSink(fireAlert) }

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
