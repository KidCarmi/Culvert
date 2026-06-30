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
