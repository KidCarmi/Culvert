// Package alerts is the producer-facing seam for security alerting. It owns the
// alert Payload DTO and a publish-once dispatch indirection, so alert producers
// (the scan engines, policy, …) can fire alerts without depending on the
// webhook-delivery implementation, which stays in package main and is installed
// once at startup via SetSink. ADR-0002/0003 (sibling to the obs sink seam).
package alerts

import "sync/atomic"

// Payload is the JSON body delivered to webhooks for a security event.
type Payload struct {
	Event     string `json:"event"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"` // client IP or username
	Host      string `json:"host"`
	Detail    string `json:"detail"` // virus name / rule name / pattern
	Source    string `json:"source"` // "clamav","yara","threatfeed","policy","auth"
}

// Sink dispatches an alert. The real implementation (webhook fan-out, retry,
// HMAC signing, SSRF-guarded delivery) lives in package main.
type Sink func(event string, p Payload)

var sink atomic.Pointer[Sink]

// SetSink installs the dispatch implementation. Intended to be called once at
// startup (publish-once); a later call atomically replaces the sink.
func SetSink(fn Sink) { sink.Store(&fn) }

// Fire dispatches an alert through the installed sink. It is a no-op when no
// sink is installed (e.g. unit tests that never wire alerting), so producers
// never need a nil check or a dependency on the delivery layer.
func Fire(event string, p Payload) {
	if s := sink.Load(); s != nil {
		(*s)(event, p)
	}
}

// SubscriberProbe reports whether any enabled webhook subscribes to event. The
// real implementation is *Store.HasSubscriber, installed from package main.
type SubscriberProbe func(event string) bool

var probe atomic.Pointer[SubscriberProbe]

// SetSubscriberProbe installs the subscription query (publish-once, same
// lifecycle as SetSink).
func SetSubscriberProbe(fn SubscriberProbe) { probe.Store(&fn) }

// HasSubscriber reports whether firing event would reach anyone, so a producer
// on the request path can skip the goroutine, the payload build and the round
// trip through the process-wide dedup mutex when — as in the default posture —
// no webhook is configured. This is the internal-package half of the contract
// package main's fireDNSFailureAlert documents: producers whose rate is set by
// a FAULT rather than by the operator must gate, because the fault puts every
// request on that path and the alert would otherwise degrade the node hardest
// exactly when it is already degraded.
//
// It fails toward DELIVERY: with no probe installed (unit tests that wire a
// sink but no store, and any call ordering where the store is not yet up) the
// answer is true, so a missing probe can never silence a real alert.
func HasSubscriber(event string) bool {
	if p := probe.Load(); p != nil {
		return (*p)(event)
	}
	return true
}
